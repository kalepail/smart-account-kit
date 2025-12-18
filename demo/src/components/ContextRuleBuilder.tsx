import { useState, useCallback, useEffect, useMemo } from "react";
import type { SmartAccountKit, StoredCredential, AssembledTransaction } from "smart-account-kit";
import {
  createDelegatedSigner,
  createWebAuthnSigner,
  createDefaultContext,
  createCallContractContext,
  createCreateContractContext,
  createThresholdParams,
  createSpendingLimitParams,
  createWeightedThresholdParams,
  LEDGERS_PER_DAY,
  getCredentialIdFromSigner,
  formatSignerForDisplay,
  signersEqual,
} from "smart-account-kit";
import { rpc, xdr, Address, scValToNative } from "@stellar/stellar-sdk";
import type { ContextRule, Signer, ContextRuleType } from "smart-account-kit-bindings";
import type { ConnectedWallet } from "smart-account-kit";
import { SignerPicker, type SelectedSigner } from "./SignerPicker";

// Configuration for RPC
const RPC_URL = import.meta.env.VITE_RPC_URL || "https://soroban-testnet.stellar.org";

/**
 * Build a ledger key for policy contract storage.
 *
 * Policy contracts store data with keys like:
 * - SimpleThresholdStorageKey::AccountContext(Address, u32)
 * - SpendingLimitStorageKey::AccountContext(Address, u32)
 * - WeightedThresholdStorageKey::AccountContext(Address, u32)
 *
 * These are Soroban enum variants serialized as ScVal.
 */
function buildPolicyStorageKey(
  policyAddress: string,
  smartAccountAddress: string,
  contextRuleId: number
): xdr.LedgerKey {
  // Build the storage key: EnumVariant("AccountContext", [Address, u32])
  // The enum variant name is "AccountContext" with tuple of (smart_account, context_rule_id)
  const storageKey = xdr.ScVal.scvVec([
    xdr.ScVal.scvSymbol("AccountContext"),
    new Address(smartAccountAddress).toScVal(),
    xdr.ScVal.scvU32(contextRuleId),
  ]);

  return xdr.LedgerKey.contractData(
    new xdr.LedgerKeyContractData({
      contract: new Address(policyAddress).toScAddress(),
      key: storageKey,
      durability: xdr.ContractDataDurability.persistent(),
    })
  );
}

/**
 * Query on-chain policy params using getLedgerEntries RPC call.
 * This directly reads the contract storage without simulation.
 */
async function queryPolicyParams(
  policyAddress: string,
  policyType: string,
  contextRuleId: number,
  smartAccountAddress: string
): Promise<{ threshold?: number; spendingLimit?: string; spendingPeriodDays?: number; weightedThreshold?: number } | null> {
  try {
    const server = new rpc.Server(RPC_URL);

    // Build the ledger key for this policy's storage
    const ledgerKey = buildPolicyStorageKey(policyAddress, smartAccountAddress, contextRuleId);

    // Query the ledger entry
    const response = await server.getLedgerEntries(ledgerKey);

    if (!response.entries || response.entries.length === 0) {
      console.warn(`No ledger entry found for ${policyType} policy`);
      return null;
    }

    // Parse the contract data entry
    const entry = response.entries[0];
    const dataEntry = entry.val.contractData();
    const value = scValToNative(dataEntry.val());

    if (policyType === "threshold") {
      // SimpleThresholdAccountParams just stores threshold: u32
      return { threshold: Number(value) };
    } else if (policyType === "spending_limit") {
      // SpendingLimitData has: spending_limit (i128), period_ledgers (u32), spending_history, cached_total_spent
      const spendingLimitStroops = BigInt(value.spending_limit);
      const periodLedgers = Number(value.period_ledgers);
      // Convert stroops to XLM (divide by 10^7)
      const spendingLimitXlm = Number(spendingLimitStroops) / 10_000_000;
      // Convert ledgers to days (17280 ledgers per day)
      const periodDays = Math.round(periodLedgers / LEDGERS_PER_DAY);
      return {
        spendingLimit: spendingLimitXlm.toString(),
        spendingPeriodDays: periodDays || 1,
      };
    } else if (policyType === "weighted_threshold") {
      // WeightedThresholdData stores threshold and signer weights
      // For now just return the threshold
      return { weightedThreshold: Number(value.threshold || value) };
    }

    return null;
  } catch (error) {
    console.warn(`Error querying ${policyType} policy params:`, error);
    return null;
  }
}

/** Policy type definition */
type PolicyInfo = {
  type: "threshold" | "spending_limit" | "weighted_threshold" | "custom";
  name: string;
  address: string;
};

interface ContextRuleBuilderProps {
  kit: SmartAccountKit;
  isOpen: boolean;
  onClose: () => void;
  onLog: (message: string, type?: "info" | "success" | "error") => void;
  onSuccess: () => void;
  editingRule?: ContextRule | null;
  /** Available policy contracts */
  availablePolicies: PolicyInfo[];
  /** WebAuthn verifier address for passkey signers */
  webauthnVerifierAddress: string;
  /** Current active credential ID (to highlight in signer list) */
  activeCredentialId?: string | null;
  /** All existing signers from on-chain context rules */
  existingSigners?: Signer[];
  /** Pending credentials from SDK storage */
  pendingCredentials?: StoredCredential[];
  /** All connected wallets */
  connectedWallets: ConnectedWallet[];
  /** Function to connect external wallet */
  connectWallet: () => Promise<ConnectedWallet | null>;
  /** Function to disconnect external wallet by address */
  disconnectWalletByAddress: (address: string) => void;
}

type SignerEntry = {
  id: string; // Unique ID for React keys
  type: "delegated" | "passkey";
  address?: string; // G-address for delegated
  credentialId?: string; // For passkeys
  publicKey?: Uint8Array; // For passkeys
  label: string;
  signer?: Signer; // Original signer object for existing signers
  isActive?: boolean; // Whether this is the currently active signer
};

type SignerAddMode = "existing" | "new_passkey" | "g_address" | "connected_wallet";
type ContextTypeOption = "default" | "call_contract" | "create_contract";

/**
 * Format a signer label using SDK utility
 */
function formatSignerLabel(signer: Signer): string {
  const { type, display } = formatSignerForDisplay(signer);
  if (type === "Passkey") {
    return `Passkey ${display}`;
  }
  return display;
}

/** Selected policy with its config */
type SelectedPolicy = {
  policy: PolicyInfo;
  // Threshold policy params
  threshold?: number;
  // Spending limit params
  spendingLimit?: string;
  spendingPeriodDays?: number;
  // Weighted threshold params
  weightedThreshold?: number;
  signerWeights?: Map<string, number>; // Maps signer ID to weight
  // Custom policy params (JSON string for now)
  customParams?: string;
  // Whether the user has modified this policy's params (only update modified policies)
  modified?: boolean;
};

export function ContextRuleBuilder({
  kit,
  isOpen,
  onClose,
  onLog,
  onSuccess,
  editingRule,
  availablePolicies,
  webauthnVerifierAddress,
  activeCredentialId,
  existingSigners = [],
  pendingCredentials = [],
  connectedWallets,
  connectWallet,
  disconnectWalletByAddress,
}: ContextRuleBuilderProps) {
  // Form state
  const [name, setName] = useState(editingRule?.name || "");
  const [contextType, setContextType] = useState<ContextTypeOption>("default");
  const [contractAddress, setContractAddress] = useState("");
  const [wasmHash, setWasmHash] = useState("");
  const [signers, setSigners] = useState<SignerEntry[]>([]);

  // Signer add state
  const [addMode, setAddMode] = useState<SignerAddMode>("existing");
  const [selectedSignerId, setSelectedSignerId] = useState<string>(""); // credentialId or address
  const [newPasskeyName, setNewPasskeyName] = useState("");
  const [gAddress, setGAddress] = useState("");
  const [addingPasskey, setAddingPasskey] = useState(false);

  // Policy state - now supports multiple policies
  const [selectedPolicies, setSelectedPolicies] = useState<SelectedPolicy[]>([]);
  const [selectedPolicyToAdd, setSelectedPolicyToAdd] = useState<string>("");  // Policy address to add

  // Expiration
  const [hasExpiration, setHasExpiration] = useState(false);
  const [expirationLedgers, setExpirationLedgers] = useState(LEDGERS_PER_DAY * 30);

  // UI state
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Signer picker state for multi-signer operations
  const [signerPickerOpen, setSignerPickerOpen] = useState(false);
  const [pendingSubmit, setPendingSubmit] = useState(false);

  const isEditing = !!editingRule;

  /**
   * Build SelectedSigner array from existing signers for multi-signer operations.
   * Uses SDK's built-in helper.
   */
  const buildSelectedSigners = useCallback((): SelectedSigner[] => {
    return kit.multiSigners.buildSelectedSigners(existingSigners, activeCredentialId);
  }, [existingSigners, kit, activeCredentialId]);

  /**
   * Check if multi-signer flow is needed.
   * Uses SDK's built-in helper.
   */
  const needsMultiSigner = useCallback((): boolean => {
    return kit.multiSigners.needsMultiSigner(existingSigners);
  }, [existingSigners, kit]);

  /**
   * Sign and submit a transaction, using multi-signer flow if needed.
   * @param tx The transaction to sign and submit
   * @param selectedSigners Optional array of selected signers (from SignerPicker)
   */
  const signAndSubmitWithMultiSigner = useCallback(
    async (tx: AssembledTransaction<unknown>, selectedSigners?: SelectedSigner[]): Promise<{ success: boolean; error?: string }> => {
      // If no signers provided and not multi-signer, use simple flow
      if (!selectedSigners && !needsMultiSigner()) {
        return kit.signAndSubmit(tx);
      }

      // Multi-signer flow - use SDK's built-in multi-signer operation
      const signers = selectedSigners || buildSelectedSigners();
      const result = await kit.multiSigners.operation(tx, signers, {
        onLog,
      });

      return {
        success: result.success,
        error: result.error,
      };
    },
    [kit, onLog, needsMultiSigner, buildSelectedSigners]
  );

  // Reset form when modal opens/closes
  useEffect(() => {
    if (isOpen) {
      if (editingRule) {
        // Editing mode - populate form with existing rule data
        setName(editingRule.name || "");

        // Load context type
        if (editingRule.context_type.tag === "CallContract") {
          setContextType("call_contract");
          setContractAddress(editingRule.context_type.values[0] as string);
        } else if (editingRule.context_type.tag === "CreateContract") {
          setContextType("create_contract");
          // Convert BytesN<32> to hex string
          const hashBytes = editingRule.context_type.values[0] as Buffer;
          setWasmHash(hashBytes.toString("hex"));
        } else {
          setContextType("default");
          setContractAddress("");
          setWasmHash("");
        }

        // Load signers from the rule
        const loadedSigners: SignerEntry[] = editingRule.signers.map((signer) => ({
          id: crypto.randomUUID(),
          type: signer.tag === "Delegated" ? "delegated" as const : "passkey" as const,
          address: signer.tag === "Delegated" ? (signer.values[0] as string) : undefined,
          credentialId: getCredentialIdFromSigner(signer) || undefined,
          label: formatSignerLabel(signer),
          signer: signer,
          isActive: getCredentialIdFromSigner(signer) === activeCredentialId,
        }));
        setSigners(loadedSigners);

        // Load expiration
        setHasExpiration(!!editingRule.valid_until);
        if (editingRule.valid_until) {
          setExpirationLedgers(editingRule.valid_until);
        }

        // Load policies from the rule - query on-chain params for each
        const loadPolicies = async () => {
          const loadedPolicies: SelectedPolicy[] = [];
          const smartAccountAddress = kit.contractId;

          for (const policyAddress of editingRule.policies) {
            const knownPolicy = availablePolicies.find((p) => p.address === policyAddress);

            if (knownPolicy && smartAccountAddress) {
              // Query on-chain params for known policy types
              const onChainParams = await queryPolicyParams(
                policyAddress,
                knownPolicy.type,
                editingRule.id,
                smartAccountAddress
              );

              loadedPolicies.push({
                policy: knownPolicy,
                // Use on-chain values if available, otherwise defaults
                threshold: onChainParams?.threshold ?? 1,
                spendingLimit: onChainParams?.spendingLimit ?? "1000",
                spendingPeriodDays: onChainParams?.spendingPeriodDays ?? 1,
                weightedThreshold: onChainParams?.weightedThreshold ?? 1,
                signerWeights: new Map(),
                customParams: "{}",
                // Only mark modified if we couldn't fetch on-chain params
                modified: !onChainParams,
              });
            } else {
              // Unknown policy - add as custom
              loadedPolicies.push({
                policy: {
                  type: "custom",
                  name: `Policy ${policyAddress.slice(0, 8)}...`,
                  address: policyAddress,
                },
                customParams: "{}",
                modified: true,
              });
            }
          }
          setSelectedPolicies(loadedPolicies);
        };

        loadPolicies();
      } else {
        // Create mode - reset form
        setName("");
        setContextType("default");
        setContractAddress("");
        setWasmHash("");
        setSigners([]);
        setSelectedPolicies([]);
        setHasExpiration(false);
      }
      setError(null);
      setSelectedPolicyToAdd("");
      setSelectedSignerId(""); // Will be set to first available when entries are computed
    }
  }, [isOpen, editingRule, activeCredentialId]);

  // Define type for signer entries
  type SignerEntryInfo = {
    id: string; // Unique ID: credentialId for passkeys, address for delegated
    signer?: Signer;
    label: string;
    type: "passkey" | "delegated";
    credentialId: string | null;
    address?: string; // G-address for delegated signers
    publicKey?: Uint8Array;
    isActive: boolean;
    isPending: boolean;
  };

  // Memoize the signer entries computation to avoid recalculating on every render
  const existingSignerEntries: SignerEntryInfo[] = useMemo(() => {
    // Convert existing signers to a list with active status
    const onChainSignerEntries: SignerEntryInfo[] = existingSigners.map((signer) => {
      const credId = getCredentialIdFromSigner(signer);
      const isActive = credId ? credId === activeCredentialId : false;
      const isDelegated = signer.tag === "Delegated";
      const address = isDelegated ? (signer.values[0] as string) : undefined;
      // Use credentialId for passkeys, address for delegated as unique ID
      const id = credId || address || crypto.randomUUID();
      return {
        id,
        signer,
        label: formatSignerLabel(signer),
        type: isDelegated ? "delegated" as const : "passkey" as const,
        credentialId: credId,
        address,
        isActive,
        isPending: false,
      };
    });

    // Add pending credentials from SDK storage
    const pendingSignerEntries: SignerEntryInfo[] = pendingCredentials
      .filter((pc) => !onChainSignerEntries.some((e) => e.credentialId === pc.credentialId))
      .map((pc) => ({
        id: pc.credentialId, // Use credentialId as unique ID
        signer: undefined,
        label: `${pc.nickname || pc.credentialId.slice(0, 8)} (pending)`,
        type: "passkey" as const,
        credentialId: pc.credentialId,
        publicKey: pc.publicKey,
        isActive: false,
        isPending: true,
      }));

    return [...onChainSignerEntries, ...pendingSignerEntries];
  }, [existingSigners, activeCredentialId, pendingCredentials]);

  const handleAddExistingSigner = useCallback(() => {
    // Find the entry by its unique ID
    const entry = existingSignerEntries.find((e) => e.id === selectedSignerId);
    if (!entry) {
      setError("Please select a signer");
      return;
    }

    // Check for duplicates before adding (by credentialId or address)
    if (entry.credentialId && signers.some((s) => s.credentialId === entry.credentialId)) {
      setError("This signer is already added");
      return;
    }
    if (entry.address && signers.some((s) => s.address === entry.address)) {
      setError("This signer is already added");
      return;
    }

    // Build the new signer entry
    let newSigner: SignerEntry;
    if (entry.isPending && entry.publicKey) {
      // Handle pending passkeys (no signer object, but have publicKey)
      newSigner = {
        id: crypto.randomUUID(),
        type: "passkey" as const,
        credentialId: entry.credentialId || undefined,
        publicKey: entry.publicKey,
        label: entry.label.replace(" (pending)", ""), // Remove pending suffix
        isActive: false,
      };
    } else {
      // On-chain signer
      newSigner = {
        id: crypto.randomUUID(),
        type: entry.type,
        address: entry.address,
        credentialId: entry.credentialId || undefined,
        label: entry.label + (entry.isActive ? " (active)" : ""),
        signer: entry.signer,
        isActive: entry.isActive,
      };
    }

    // Add the signer
    setSigners([...signers, newSigner]);
    setError(null);

    // Reset to next available signer
    const nextAvailable = existingSignerEntries.find((e) => {
      if (e.id === entry.id) return false; // Skip the one we just added
      // Check if not already in signers
      if (e.credentialId && signers.some((s) => s.credentialId === e.credentialId)) return false;
      if (e.address && signers.some((s) => s.address === e.address)) return false;
      return true;
    });
    if (nextAvailable) {
      setSelectedSignerId(nextAvailable.id);
    }
  }, [selectedSignerId, existingSignerEntries, signers]);

  const handleCreateNewPasskey = useCallback(async () => {
    setAddingPasskey(true);
    setError(null);

    try {
      const label = newPasskeyName.trim() || `Signer ${signers.length + 1}`;

      // Use SDK's credential creation - handles WebAuthn, key extraction, and storage
      const credential = await kit.credentials.create({
        nickname: label,
        appName: "Smart Account Demo",
      });

      // Add it to our signers list
      setSigners([
        ...signers,
        {
          id: crypto.randomUUID(),
          type: "passkey",
          credentialId: credential.credentialId,
          publicKey: credential.publicKey,
          label,
        },
      ]);

      setNewPasskeyName("");
      onLog(`Created new passkey: ${label}`, "success");
      onLog(`Passkey saved locally - will persist if submission fails`, "info");
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to create passkey";
      setError(message);
      onLog(`Failed to create passkey: ${message}`, "error");
    } finally {
      setAddingPasskey(false);
    }
  }, [kit, newPasskeyName, signers, onLog]);

  const handleAddGAddress = useCallback(() => {
    const address = gAddress.trim();

    if (!address.startsWith("G") || address.length !== 56) {
      setError("Invalid Stellar address. Must start with G and be 56 characters.");
      return;
    }

    // Check for duplicates
    if (signers.some((s) => s.type === "delegated" && s.address === address)) {
      setError("This signer is already added");
      return;
    }

    setSigners([
      ...signers,
      {
        id: crypto.randomUUID(),
        type: "delegated",
        address,
        label: `${address.slice(0, 8)}...${address.slice(-8)}`,
      },
    ]);
    setGAddress("");
    setError(null);
  }, [gAddress, signers]);

  const handleAddConnectedWallet = useCallback((wallet: ConnectedWallet) => {
    const address = wallet.address;

    // Check for duplicates
    if (signers.some((s) => s.type === "delegated" && s.address === address)) {
      setError("This wallet is already added as a signer");
      return;
    }

    const walletLabel = `${wallet.walletName}: ${address.slice(0, 8)}...${address.slice(-8)}`;

    setSigners([
      ...signers,
      {
        id: crypto.randomUUID(),
        type: "delegated",
        address,
        label: walletLabel,
      },
    ]);
    setError(null);
    onLog(`Added ${wallet.walletName} (${address.slice(0, 8)}...) as signer`, "success");
  }, [signers, onLog]);

  const handleRemoveSigner = (id: string) => {
    setSigners(signers.filter((s) => s.id !== id));
  };

  /**
   * Execute the actual submission logic
   * @param selectedSigners Optional signers from SignerPicker (for multi-signer flow)
   */
  const executeSubmit = async (selectedSigners?: SelectedSigner[]) => {
    setLoading(true);
    onLog(`${isEditing ? "Updating" : "Creating"} context rule "${name}"...`);

    try {
      // Build context type
      let ctxType: ContextRuleType;
      if (contextType === "call_contract") {
        ctxType = createCallContractContext(contractAddress);
      } else if (contextType === "create_contract") {
        ctxType = createCreateContractContext(wasmHash);
      } else {
        ctxType = createDefaultContext();
      }

      // Build signers - use existing signer object if available, otherwise build new
      const builtSigners: Signer[] = [];

      for (const entry of signers) {
        if (entry.signer) {
          // Use existing signer object directly
          builtSigners.push(entry.signer);
        } else if (entry.type === "delegated" && entry.address) {
          builtSigners.push(createDelegatedSigner(entry.address));
        } else if (entry.type === "passkey" && entry.publicKey && entry.credentialId) {
          builtSigners.push(
            createWebAuthnSigner(webauthnVerifierAddress, entry.publicKey, entry.credentialId)
          );
        }
      }

      // Build policies map - convert params to ScVal for on-chain submission
      const policies = new Map<string, unknown>();

      for (const sp of selectedPolicies) {
        let nativeParams: unknown;

        if (sp.policy.type === "threshold") {
          nativeParams = createThresholdParams(sp.threshold || 1);
        } else if (sp.policy.type === "spending_limit") {
          const limitStroops = BigInt(Math.floor(parseFloat(sp.spendingLimit || "1000") * 10_000_000));
          const periodLedgers = (sp.spendingPeriodDays || 1) * LEDGERS_PER_DAY;
          nativeParams = createSpendingLimitParams(limitStroops, periodLedgers);
        } else if (sp.policy.type === "weighted_threshold") {
          // Build signer weights map
          const weights = new Map<Signer, number>();
          if (sp.signerWeights) {
            for (const entry of signers) {
              const weight = sp.signerWeights.get(entry.id);
              if (weight && weight > 0) {
                // Get the actual signer object
                let signer: Signer | null = null;
                if (entry.signer) {
                  signer = entry.signer;
                } else if (entry.type === "delegated" && entry.address) {
                  signer = createDelegatedSigner(entry.address);
                } else if (entry.type === "passkey" && entry.publicKey && entry.credentialId) {
                  signer = createWebAuthnSigner(webauthnVerifierAddress, entry.publicKey, entry.credentialId);
                }
                if (signer) {
                  weights.set(signer, weight);
                }
              }
            }
          }
          nativeParams = createWeightedThresholdParams(sp.weightedThreshold || 1, weights);
        } else {
          // Custom policy - try to parse JSON params
          try {
            nativeParams = sp.customParams ? JSON.parse(sp.customParams) : {};
          } catch (error) {
            console.warn("Failed to parse custom policy params, using empty object:", error);
            nativeParams = {};
          }
        }

        // Convert to ScVal for known policy types (with sorted fields)
        if (sp.policy.type === "threshold" || sp.policy.type === "spending_limit" || sp.policy.type === "weighted_threshold") {
          const scValParams = kit.convertPolicyParams(sp.policy.type, nativeParams);
          policies.set(sp.policy.address, scValParams);
        } else {
          policies.set(sp.policy.address, nativeParams);
        }
      }

      // Sort policies Map by key (address) - Soroban requires ScMap keys to be sorted
      const sortedPolicies = new Map(
        [...policies.entries()].sort(([a], [b]) => a.localeCompare(b))
      );

      // Calculate expiration
      const validUntil = hasExpiration ? expirationLedgers : undefined;

      if (isEditing) {
        // Update existing rule
        const ruleId = editingRule!.id;

        // Update name if changed
        if (name.trim() !== editingRule!.name) {
          onLog(`Updating rule name...`);
          const tx = await kit.rules.updateName(ruleId, name.trim());
          const result = await signAndSubmitWithMultiSigner(tx, selectedSigners);
          if (!result.success) {
            throw new Error(result.error || "Failed to update rule name");
          }
        }

        // Find new signers (those without a pre-existing signer object)
        const newSigners = signers.filter((entry) => !entry.signer);

        // Find removed signers (those in the original rule but not in current signers)
        const removedSigners = editingRule!.signers.filter(
          (originalSigner) => !signers.some((s) => s.signer && signersEqual(s.signer, originalSigner))
        );

        // Add new signers
        for (const entry of newSigners) {
          if (entry.type === "delegated" && entry.address) {
            onLog(`Adding delegated signer ${entry.address.slice(0, 8)}...`);
            const tx = await kit.signers.addDelegated(ruleId, entry.address);
            const result = await signAndSubmitWithMultiSigner(tx, selectedSigners);
            if (!result.success) {
              throw new Error(result.error || `Failed to add delegated signer ${entry.address}`);
            }
          } else if (entry.type === "passkey" && entry.publicKey && entry.credentialId) {
            onLog(`Adding passkey signer...`);
            // Build the signer object and use the wallet client directly
            const signer = createWebAuthnSigner(webauthnVerifierAddress, entry.publicKey, entry.credentialId);
            const tx = await kit.wallet!.add_signer({
              context_rule_id: ruleId,
              signer,
            });
            const result = await signAndSubmitWithMultiSigner(tx, selectedSigners);
            if (!result.success) {
              throw new Error(result.error || "Failed to add passkey signer");
            }
            // Note: pending passkey cleanup happens in the final cleanup loop below
          }
        }

        // Remove signers that were deleted
        for (const signer of removedSigners) {
          onLog(`Removing signer...`);
          const tx = await kit.signers.remove(ruleId, signer);
          const result = await signAndSubmitWithMultiSigner(tx, selectedSigners);
          if (!result.success) {
            throw new Error(result.error || "Failed to remove signer");
          }
        }

        // Handle policy changes
        // Note: If we added new signers, policy changes may fail due to changed auth requirements
        // Skip policy changes in that case and inform the user
        const currentPolicyAddresses = selectedPolicies.map((sp) => sp.policy.address);
        const originalPolicyAddresses = editingRule!.policies;

        // Find policies to add (in current but not in original)
        const policiesToAdd = selectedPolicies.filter(
          (sp) => !originalPolicyAddresses.includes(sp.policy.address)
        );

        // Find policies to remove (in original but not in current)
        const policiesToRemove = originalPolicyAddresses.filter(
          (addr) => !currentPolicyAddresses.includes(addr)
        );

        // Find policies to update (exist in both AND user has modified them)
        // Only update policies that the user explicitly changed params on
        const policiesToUpdate = selectedPolicies.filter(
          (sp) => originalPolicyAddresses.includes(sp.policy.address) && sp.modified
        );

        const hasPolicyChanges = policiesToAdd.length > 0 || policiesToRemove.length > 0 || policiesToUpdate.length > 0;
        const addedNewSigners = newSigners.length > 0;

        if (hasPolicyChanges && addedNewSigners) {
          onLog(`Note: Policy changes skipped - please update policies separately after adding signers`, "info");
        } else {
          // Remove policies first (includes those being removed and those being updated)
          for (const policyAddress of policiesToRemove) {
            onLog(`Removing policy ${policyAddress.slice(0, 8)}...`);
            const tx = await kit.policies.remove(ruleId, policyAddress);
            const result = await signAndSubmitWithMultiSigner(tx, selectedSigners);
            if (!result.success) {
              throw new Error(result.error || `Failed to remove policy ${policyAddress}`);
            }
          }

          // Remove policies that will be updated (so we can re-add with new params)
          for (const sp of policiesToUpdate) {
            onLog(`Updating policy ${sp.policy.name}...`);
            const removeTx = await kit.policies.remove(ruleId, sp.policy.address);
            const removeResult = await signAndSubmitWithMultiSigner(removeTx, selectedSigners);
            if (!removeResult.success) {
              throw new Error(removeResult.error || `Failed to update policy ${sp.policy.name}`);
            }
          }

          // Helper function to build install params for a policy
          const buildInstallParams = (sp: SelectedPolicy): unknown => {
            if (sp.policy.type === "threshold") {
              return createThresholdParams(sp.threshold || 1);
            } else if (sp.policy.type === "spending_limit") {
              const limitStroops = BigInt(Math.floor(parseFloat(sp.spendingLimit || "1000") * 10_000_000));
              const periodLedgers = (sp.spendingPeriodDays || 1) * LEDGERS_PER_DAY;
              return createSpendingLimitParams(limitStroops, periodLedgers);
            } else if (sp.policy.type === "weighted_threshold") {
              // Build signer weights map
              const weights = new Map<Signer, number>();
              if (sp.signerWeights) {
                for (const entry of signers) {
                  const weight = sp.signerWeights.get(entry.id);
                  if (weight && weight > 0) {
                    let signer: Signer | null = null;
                    if (entry.signer) {
                      signer = entry.signer;
                    } else if (entry.type === "delegated" && entry.address) {
                      signer = createDelegatedSigner(entry.address);
                    } else if (entry.type === "passkey" && entry.publicKey && entry.credentialId) {
                      signer = createWebAuthnSigner(webauthnVerifierAddress, entry.publicKey, entry.credentialId);
                    }
                    if (signer) {
                      weights.set(signer, weight);
                    }
                  }
                }
              }
              return createWeightedThresholdParams(sp.weightedThreshold || 1, weights);
            } else {
              // Custom policy - for unknown types, user must provide properly formatted params
              try {
                return sp.customParams ? JSON.parse(sp.customParams) : {};
              } catch (error) {
                console.warn("Failed to parse custom policy params:", error);
                return {};
              }
            }
          };

          // Helper function to add a policy
          const addPolicy = async (sp: SelectedPolicy) => {
            const installParams = buildInstallParams(sp);

            // Convert params to ScVal using the contract spec (for known policy types)
            // This is needed because add_policy uses Val (any) type for install_param
            let scValParams: unknown;
            if (sp.policy.type === "threshold" || sp.policy.type === "spending_limit" || sp.policy.type === "weighted_threshold") {
              scValParams = kit.convertPolicyParams(sp.policy.type, installParams);
            } else {
              // Custom policy - pass params as-is
              scValParams = installParams;
            }

            const tx = await kit.policies.add(ruleId, sp.policy.address, scValParams);
            const result = await signAndSubmitWithMultiSigner(tx, selectedSigners);
            if (!result.success) {
              throw new Error(result.error || `Failed to add policy ${sp.policy.name}`);
            }
          };

          // Re-add policies that were updated with new params
          for (const sp of policiesToUpdate) {
            await addPolicy(sp);
          }

          // Add new policies
          for (const sp of policiesToAdd) {
            onLog(`Adding policy ${sp.policy.name}...`);
            await addPolicy(sp);
          }
        }

        // Update expiration if changed
        // Be careful with comparison - undefined, null, and 0 should all be treated as "no expiration"
        const originalExpiration = editingRule!.valid_until || undefined;
        const newExpiration = validUntil || undefined;
        const expirationChanged = originalExpiration !== newExpiration;

        // Only update expiration if it actually changed AND we didn't add new signers
        // (adding signers changes the auth requirements, which could cause the next operation to fail)
        if (expirationChanged && !addedNewSigners) {
          onLog(`Updating expiration...`);
          const tx = await kit.rules.updateExpiration(ruleId, validUntil);
          const result = await signAndSubmitWithMultiSigner(tx, selectedSigners);
          if (!result.success) {
            throw new Error(result.error || "Failed to update expiration");
          }
        } else if (expirationChanged && addedNewSigners) {
          onLog(`Note: Expiration update skipped - please update expiration separately after adding signers`, "info");
        }

        onLog(`Context rule "${name}" updated!`, "success");
      } else {
        // Create new rule
        const tx = await kit.rules.add(ctxType, name.trim(), builtSigners, sortedPolicies, validUntil);
        const result = await signAndSubmitWithMultiSigner(tx, selectedSigners);
        if (!result.success) {
          throw new Error(result.error || "Failed to create rule");
        }
        onLog(`Context rule "${name}" created!`, "success");
      }

      // Clean up any pending passkeys that were successfully added
      for (const entry of signers) {
        if (entry.type === "passkey" && entry.credentialId && !entry.signer) {
          // This was a pending passkey - remove it from SDK storage
          await kit.credentials.delete(entry.credentialId);
          onLog(`Cleaned up pending passkey: ${entry.label}`, "info");
        }
      }

      onSuccess();
      onClose();
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unknown error";
      setError(message);
      onLog(`Failed to ${isEditing ? "update" : "create"} rule: ${message}`, "error");
    } finally {
      setLoading(false);
      setPendingSubmit(false);
    }
  };

  /**
   * Handle form submission - validates and either proceeds directly or shows SignerPicker
   */
  const handleSubmit = async () => {
    setError(null);

    // Validation
    if (!name.trim()) {
      setError("Rule name is required.");
      return;
    }

    if (contextType === "call_contract") {
      if (!contractAddress.startsWith("C") || contractAddress.length !== 56) {
        setError("Invalid contract address. Must start with C and be 56 characters.");
        return;
      }
    }

    if (contextType === "create_contract") {
      const cleanHash = wasmHash.startsWith("0x") ? wasmHash.slice(2) : wasmHash;
      if (cleanHash.length !== 64 || !/^[0-9a-fA-F]+$/.test(cleanHash)) {
        setError("Invalid WASM hash. Must be 64 hex characters (32 bytes).");
        return;
      }
    }

    if (signers.length === 0 && selectedPolicies.length === 0) {
      setError("At least one signer or policy is required.");
      return;
    }

    // Validate threshold policies
    const thresholdPolicies = selectedPolicies.filter((p) => p.policy.type === "threshold");
    for (const tp of thresholdPolicies) {
      if ((tp.threshold || 1) > signers.length) {
        setError(`Threshold (${tp.threshold || 1}) cannot exceed number of signers (${signers.length}).`);
        return;
      }
    }

    // Check if multi-signer flow is needed - show signer picker
    if (needsMultiSigner()) {
      setPendingSubmit(true);
      setSignerPickerOpen(true);
      return;
    }

    // Single signer flow - proceed directly
    await executeSubmit();
  };

  /**
   * Handle SignerPicker confirmation - proceeds with submission using selected signers
   */
  const handleSignerPickerConfirm = (selectedSigners: SelectedSigner[]) => {
    setSignerPickerOpen(false);
    if (pendingSubmit) {
      executeSubmit(selectedSigners);
    }
  };

  /**
   * Handle SignerPicker close without confirming
   */
  const handleSignerPickerClose = () => {
    setSignerPickerOpen(false);
    setPendingSubmit(false);
  };

  // Compute available signers (those not already added)
  const availableExistingSigners = useMemo(() => {
    return existingSignerEntries.filter((entry) => {
      // Check by credentialId (for passkeys)
      if (entry.credentialId && signers.some((s) => s.credentialId === entry.credentialId)) {
        return false;
      }
      // Check by address (for delegated signers)
      if (entry.address && signers.some((s) => s.address === entry.address)) {
        return false;
      }
      return true;
    });
  }, [existingSignerEntries, signers]);

  // Set initial selected signer ID when available signers change
  useEffect(() => {
    if (isOpen && availableExistingSigners.length > 0) {
      // If current selection is not in available list, select the first one
      if (!selectedSignerId || !availableExistingSigners.some((e) => e.id === selectedSignerId)) {
        setSelectedSignerId(availableExistingSigners[0].id);
      }
    }
  }, [isOpen, availableExistingSigners, selectedSignerId]);

  if (!isOpen) return null;

  return (
  <>
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h3>{isEditing ? "Edit Context Rule" : "Create Context Rule"}</h3>
          <button className="modal-close" onClick={onClose}>
            &times;
          </button>
        </div>

        <div className="modal-body">
          {error && <div className="error-banner">{error}</div>}

          {/* Rule Name */}
          <div className="form-group">
            <label>Rule Name *</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g., Primary Signers, Trading Bot, Daily Spending"
            />
          </div>

          {/* Context Type */}
          <div className="form-group">
            <label>Context Type</label>
            <div className="radio-group">
              <label className="radio-label">
                <input
                  type="radio"
                  name="contextType"
                  value="default"
                  checked={contextType === "default"}
                  onChange={() => setContextType("default")}
                />
                <span>Default (Any Operation)</span>
              </label>
              <label className="radio-label">
                <input
                  type="radio"
                  name="contextType"
                  value="call_contract"
                  checked={contextType === "call_contract"}
                  onChange={() => setContextType("call_contract")}
                />
                <span>Call Contract</span>
              </label>
              <label className="radio-label">
                <input
                  type="radio"
                  name="contextType"
                  value="create_contract"
                  checked={contextType === "create_contract"}
                  onChange={() => setContextType("create_contract")}
                />
                <span>Create Contract</span>
              </label>
            </div>
            {contextType === "call_contract" && (
              <input
                type="text"
                value={contractAddress}
                onChange={(e) => setContractAddress(e.target.value)}
                placeholder="Contract address (C...)"
                style={{ marginTop: "8px" }}
              />
            )}
            {contextType === "create_contract" && (
              <input
                type="text"
                value={wasmHash}
                onChange={(e) => setWasmHash(e.target.value)}
                placeholder="WASM hash (64 hex chars, e.g., abc123...)"
                style={{ marginTop: "8px" }}
              />
            )}
          </div>

          {/* Signers */}
          <div className="form-group">
            <label>Signers</label>
            <p className="form-hint">
              Add accounts that can authorize transactions under this rule.
            </p>

            {/* Current signers list */}
            {signers.length > 0 && (
              <div className="signer-list">
                {signers.map((signer) => {
                  // Check if this delegated signer matches any connected wallet
                  const matchingWallet = signer.type === "delegated" && signer.address
                    ? connectedWallets.find((w) => w.address === signer.address)
                    : undefined;

                  return (
                    <div key={signer.id} className={`signer-item ${signer.isActive ? "active" : ""} ${matchingWallet ? "connected" : ""}`}>
                      <span className="signer-type-badge">
                        {signer.type === "delegated" ? "G-Address" : "Passkey"}
                      </span>
                      <span className="signer-value">
                        {signer.label}
                        {signer.isActive && <span className="active-badge">active</span>}
                        {matchingWallet && <span className="connected-badge">{matchingWallet.walletName}</span>}
                      </span>
                      <button
                        className="remove-btn"
                        onClick={() => handleRemoveSigner(signer.id)}
                        title="Remove signer"
                      >
                        &times;
                      </button>
                    </div>
                  );
                })}
              </div>
            )}

            {/* Add signer section */}
            <div className="add-signer-section">
              <div className="signer-mode-tabs">
                <button
                  className={`mode-tab ${addMode === "existing" ? "active" : ""}`}
                  onClick={() => setAddMode("existing")}
                  disabled={addingPasskey}
                >
                  Existing
                </button>
                <button
                  className={`mode-tab ${addMode === "new_passkey" ? "active" : ""}`}
                  onClick={() => setAddMode("new_passkey")}
                  disabled={addingPasskey}
                >
                  New Passkey
                </button>
                <button
                  className={`mode-tab ${addMode === "connected_wallet" ? "active" : ""}`}
                  onClick={() => setAddMode("connected_wallet")}
                  disabled={addingPasskey}
                >
                  Connected Wallet
                </button>
                <button
                  className={`mode-tab ${addMode === "g_address" ? "active" : ""}`}
                  onClick={() => setAddMode("g_address")}
                  disabled={addingPasskey}
                >
                  Manual G-Address
                </button>
              </div>

              <div className="signer-mode-content">
                {addMode === "existing" && (
                  <div className="add-signer-row">
                    {availableExistingSigners.length > 0 ? (
                      <>
                        <select
                          value={selectedSignerId}
                          onChange={(e) => setSelectedSignerId(e.target.value)}
                          disabled={addingPasskey}
                        >
                          {availableExistingSigners.map((entry) => (
                            <option key={entry.id} value={entry.id}>
                              {entry.label} ({entry.type})
                              {entry.isActive && " * active"}
                            </option>
                          ))}
                        </select>
                        <button
                          className="small"
                          onClick={handleAddExistingSigner}
                          disabled={addingPasskey}
                        >
                          Add
                        </button>
                      </>
                    ) : (
                      <span className="no-credentials">
                        {existingSignerEntries.length === 0
                          ? "No existing signers found on-chain."
                          : "All existing signers already added."}
                      </span>
                    )}
                  </div>
                )}

                {addMode === "new_passkey" && (
                  <div className="add-signer-row">
                    <input
                      type="text"
                      value={newPasskeyName}
                      onChange={(e) => setNewPasskeyName(e.target.value)}
                      placeholder="Passkey name (optional)"
                      disabled={addingPasskey}
                    />
                    <button
                      className="small"
                      onClick={handleCreateNewPasskey}
                      disabled={addingPasskey}
                    >
                      {addingPasskey ? <span className="spinner" /> : "Create"}
                    </button>
                  </div>
                )}

                {addMode === "connected_wallet" && (
                  <div className="connected-wallets-add-section">
                    {/* List of connected wallets */}
                    {connectedWallets.length > 0 ? (
                      <div className="connected-wallets-list">
                        {connectedWallets.map((wallet) => {
                          const isAlreadyAdded = signers.some(
                            (s) => s.type === "delegated" && s.address === wallet.address
                          );
                          return (
                            <div key={wallet.address} className="connected-wallet-item">
                              <div className="wallet-info">
                                <span className="wallet-badge">{wallet.walletName}</span>
                                <span className="wallet-address">
                                  {wallet.address.slice(0, 10)}...{wallet.address.slice(-6)}
                                </span>
                              </div>
                              <button
                                className="small"
                                onClick={() => handleAddConnectedWallet(wallet)}
                                disabled={isAlreadyAdded}
                              >
                                {isAlreadyAdded ? "Added" : "Add"}
                              </button>
                            </div>
                          );
                        })}
                      </div>
                    ) : (
                      <div className="no-wallets-message">
                        <span className="no-credentials">No wallets connected yet</span>
                      </div>
                    )}
                    {/* Connect another wallet button */}
                    <button
                      className="small secondary connect-more-btn"
                      onClick={() => connectWallet()}
                      style={{ marginTop: connectedWallets.length > 0 ? "12px" : "0" }}
                    >
                      {connectedWallets.length > 0 ? "+ Connect Another Wallet" : "Connect Wallet"}
                    </button>
                  </div>
                )}

                {addMode === "g_address" && (
                  <div className="add-signer-row">
                    <input
                      type="text"
                      value={gAddress}
                      onChange={(e) => setGAddress(e.target.value)}
                      placeholder="Stellar address (G...)"
                      disabled={addingPasskey}
                    />
                    <button
                      className="small"
                      onClick={handleAddGAddress}
                      disabled={addingPasskey || !gAddress}
                    >
                      Add
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Policies */}
          <div className="form-group">
            <label>Policies (Optional)</label>
            <p className="form-hint">Add authorization policies for additional security.</p>

            {/* Currently selected policies */}
            {selectedPolicies.length > 0 && (
              <div className="selected-policies-list">
                {selectedPolicies.map((sp, index) => (
                  <div key={index} className="selected-policy-item">
                    <div className="selected-policy-header">
                      <span className="policy-type-badge">{sp.policy.type}</span>
                      <span className="policy-name">{sp.policy.name}</span>
                      <button
                        className="remove-btn"
                        onClick={() => setSelectedPolicies(selectedPolicies.filter((_, i) => i !== index))}
                        title="Remove policy"
                      >
                        &times;
                      </button>
                    </div>
                    <code className="policy-address-small">{sp.policy.address}</code>

                    {/* Policy-specific params */}
                    {sp.policy.type === "threshold" && (
                      <div className="policy-params">
                        <label>
                          Required signatures:
                          <input
                            type="number"
                            min={1}
                            max={signers.length || 15}
                            value={sp.threshold || 1}
                            onChange={(e) => {
                              const newPolicies = [...selectedPolicies];
                              newPolicies[index] = { ...sp, threshold: parseInt(e.target.value) || 1, modified: true };
                              setSelectedPolicies(newPolicies);
                            }}
                            style={{ width: "60px", marginLeft: "8px" }}
                          />
                          <span style={{ marginLeft: "8px", color: "#71717a" }}>
                            of {signers.length} signers
                          </span>
                        </label>
                      </div>
                    )}

                    {sp.policy.type === "spending_limit" && (
                      <div className="policy-params">
                        <div style={{ display: "flex", gap: "12px", alignItems: "center", flexWrap: "wrap" }}>
                          <label>
                            Max:
                            <input
                              type="text"
                              value={sp.spendingLimit || "1000"}
                              onChange={(e) => {
                                const newPolicies = [...selectedPolicies];
                                newPolicies[index] = { ...sp, spendingLimit: e.target.value, modified: true };
                                setSelectedPolicies(newPolicies);
                              }}
                              style={{ width: "100px", marginLeft: "8px" }}
                            />
                            <span style={{ marginLeft: "4px" }}>XLM</span>
                          </label>
                          <label>
                            per
                            <input
                              type="number"
                              min={1}
                              value={sp.spendingPeriodDays || 1}
                              onChange={(e) => {
                                const newPolicies = [...selectedPolicies];
                                newPolicies[index] = { ...sp, spendingPeriodDays: parseInt(e.target.value) || 1, modified: true };
                                setSelectedPolicies(newPolicies);
                              }}
                              style={{ width: "60px", marginLeft: "8px" }}
                            />
                            <span style={{ marginLeft: "4px" }}>day(s)</span>
                          </label>
                        </div>
                      </div>
                    )}

                    {sp.policy.type === "weighted_threshold" && (
                      <div className="policy-params">
                        <div style={{ marginBottom: "12px" }}>
                          <label>
                            Required weight:
                            <input
                              type="number"
                              min={1}
                              value={sp.weightedThreshold || 1}
                              onChange={(e) => {
                                const newPolicies = [...selectedPolicies];
                                newPolicies[index] = { ...sp, weightedThreshold: parseInt(e.target.value) || 1, modified: true };
                                setSelectedPolicies(newPolicies);
                              }}
                              style={{ width: "80px", marginLeft: "8px" }}
                            />
                          </label>
                        </div>
                        {signers.length > 0 ? (
                          <div>
                            <div style={{ fontSize: "0.85rem", color: "#71717a", marginBottom: "8px" }}>
                              Signer weights:
                            </div>
                            {signers.map((signer) => {
                              const currentWeight = sp.signerWeights?.get(signer.id) || 0;
                              return (
                                <div key={signer.id} style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
                                  <span style={{ flex: 1, fontSize: "0.85rem", color: "#a1a1aa" }}>
                                    {signer.label}
                                  </span>
                                  <input
                                    type="number"
                                    min={0}
                                    value={currentWeight}
                                    onChange={(e) => {
                                      const newPolicies = [...selectedPolicies];
                                      const newWeights = new Map(sp.signerWeights || new Map());
                                      newWeights.set(signer.id, parseInt(e.target.value) || 0);
                                      newPolicies[index] = { ...sp, signerWeights: newWeights, modified: true };
                                      setSelectedPolicies(newPolicies);
                                    }}
                                    style={{ width: "60px" }}
                                  />
                                </div>
                              );
                            })}
                            <div style={{ fontSize: "0.8rem", color: "#52525b", marginTop: "8px" }}>
                              Total weight: {
                                signers.reduce((sum, s) => sum + (sp.signerWeights?.get(s.id) || 0), 0)
                              }
                            </div>
                          </div>
                        ) : (
                          <div style={{ fontSize: "0.85rem", color: "#71717a", fontStyle: "italic" }}>
                            Add signers above to configure weights
                          </div>
                        )}
                      </div>
                    )}

                    {sp.policy.type === "custom" && (
                      <div className="policy-params">
                        <label>
                          Install params (JSON):
                          <input
                            type="text"
                            value={sp.customParams || "{}"}
                            onChange={(e) => {
                              const newPolicies = [...selectedPolicies];
                              newPolicies[index] = { ...sp, customParams: e.target.value, modified: true };
                              setSelectedPolicies(newPolicies);
                            }}
                            placeholder="{}"
                            style={{ marginLeft: "8px", width: "200px" }}
                          />
                        </label>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}

            {/* Add policy dropdown */}
            {availablePolicies.length > 0 && (() => {
              const unselectedPolicies = availablePolicies.filter(
                (p) => !selectedPolicies.some((sp) => sp.policy.address === p.address)
              );
              // Auto-select first available policy if none selected
              const effectiveSelection = selectedPolicyToAdd && unselectedPolicies.some(p => p.address === selectedPolicyToAdd)
                ? selectedPolicyToAdd
                : unselectedPolicies[0]?.address || "";

              return (
                <div className="add-policy-section">
                  <div className="add-signer-row">
                    <select
                      value={effectiveSelection}
                      onChange={(e) => setSelectedPolicyToAdd(e.target.value)}
                    >
                      {unselectedPolicies.map((policy) => (
                        <option key={policy.address} value={policy.address}>
                          {policy.name} ({policy.type})
                        </option>
                      ))}
                    </select>
                    <button
                      className="small"
                      onClick={() => {
                        const policy = availablePolicies.find(p => p.address === effectiveSelection);
                        if (policy) {
                          setSelectedPolicies([
                            ...selectedPolicies,
                            {
                              policy,
                              threshold: 1,
                              spendingLimit: "1000",
                              spendingPeriodDays: 1,
                              weightedThreshold: 1,
                              signerWeights: new Map(),
                              customParams: "{}",
                            },
                          ]);
                          // Reset selection to next available
                          setSelectedPolicyToAdd("");
                        }
                      }}
                      disabled={unselectedPolicies.length === 0}
                    >
                      Add Policy
                    </button>
                  </div>
                </div>
              );
            })()}

            {availablePolicies.length === 0 && (
              <div className="form-hint" style={{ fontStyle: "italic" }}>
                No policy contracts configured. Enable policies in the Configuration section.
              </div>
            )}
          </div>

          {/* Expiration */}
          <div className="form-group">
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={hasExpiration}
                onChange={(e) => setHasExpiration(e.target.checked)}
              />
              <span>Set Expiration</span>
            </label>
            {hasExpiration && (
              <div style={{ marginTop: "8px" }}>
                <label>
                  Expires in:
                  <input
                    type="number"
                    min={1}
                    value={Math.round(expirationLedgers / LEDGERS_PER_DAY)}
                    onChange={(e) =>
                      setExpirationLedgers((parseInt(e.target.value) || 1) * LEDGERS_PER_DAY)
                    }
                    style={{ width: "80px", marginLeft: "8px" }}
                  />
                  <span style={{ marginLeft: "4px" }}>days</span>
                </label>
              </div>
            )}
          </div>
        </div>

        <div className="modal-footer">
          <button className="secondary" onClick={onClose} disabled={loading}>
            Cancel
          </button>
          <button onClick={handleSubmit} disabled={loading}>
            {loading ? (
              <span className="spinner" />
            ) : isEditing ? (
              "Update Rule"
            ) : (
              "Create Rule"
            )}
          </button>
        </div>
      </div>
    </div>

    {/* SignerPicker modal for multi-signer operations */}
    <SignerPicker
      isOpen={signerPickerOpen}
      onClose={handleSignerPickerClose}
      availableSigners={existingSigners}
      activeCredentialId={activeCredentialId || null}
      onConfirm={handleSignerPickerConfirm}
      title={isEditing ? "Select Signers for Update" : "Select Signers"}
      description="Choose which signers to use for this context rule operation."
      connectedWallets={connectedWallets}
      connectWallet={connectWallet}
      disconnectWalletByAddress={disconnectWalletByAddress}
    />
  </>
  );
}
