import { useState, useCallback, useEffect } from "react";
import {
  SmartAccountKit,
  IndexedDBStorage,
  getCredentialIdFromSigner,
  validateAddress,
  validateAmount,
  StellarWalletsKitAdapter,
  type StoredCredential,
  type SelectedSigner,
  type ConnectedWallet,
  type IndexedContractSummary,
} from "smart-account-kit";
import { Networks, rpc, Asset } from "@stellar/stellar-sdk";
import type { ContextRule, Signer } from "smart-account-kit-bindings";

// Import new components
import { ContextRulesPanel, ContextRuleBuilder, ActiveSignerDisplay, SignerPicker } from "./components";

// Configuration - reads from environment variables with testnet defaults
const CONFIG = {
  rpcUrl: import.meta.env.VITE_RPC_URL || "https://soroban-testnet.stellar.org",
  networkPassphrase: import.meta.env.VITE_NETWORK_PASSPHRASE || Networks.TESTNET,
  accountWasmHash: import.meta.env.VITE_ACCOUNT_WASM_HASH || "a12e8fa9621efd20315753bd4007d974390e31fbcb4a7ddc4dd0a0dec728bf2e",
  webauthnVerifierAddress: import.meta.env.VITE_WEBAUTHN_VERIFIER_ADDRESS || "CBSHV66WG7UV6FQVUTB67P3DZUEJ2KJ5X6JKQH5MFRAAFNFJUAJVXJYV",
  nativeTokenContract: import.meta.env.VITE_NATIVE_TOKEN_CONTRACT || "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC",
  ed25519VerifierAddress: import.meta.env.VITE_ED25519_VERIFIER_ADDRESS || "CDGMOL3BP6Y6LYOXXTRNXBNJ2SLNTQ47BGG3LOS2OBBE657E3NYCN54B",
  // Relayer fee sponsoring (optional)
  relayerUrl: import.meta.env.VITE_RELAYER_URL || "",
};

// Known policy contracts - reads from environment variables with testnet defaults
const KNOWN_POLICIES = [
  {
    type: "threshold" as const,
    name: "Threshold (M-of-N)",
    description: "Requires M signatures out of N total signers",
    address: import.meta.env.VITE_THRESHOLD_POLICY_ADDRESS || "CCT4MMN5MJ6O2OU6LXPYTCVORQ2QVTBMDJ7MYBZQ2ULSYQVUIYP4IFYD",
  },
  {
    type: "spending_limit" as const,
    name: "Spending Limit",
    description: "Limits spending to a maximum amount per time period",
    address: import.meta.env.VITE_SPENDING_LIMIT_POLICY_ADDRESS || "CBMMWY54XOV6JJHSWCMKWWPXVRXASR5U26UJMLZDN4SP6CFFTVZARPTY",
  },
  {
    type: "weighted_threshold" as const,
    name: "Weighted Threshold",
    description: "Requires minimum total weight from signers with different voting weights",
    address: import.meta.env.VITE_WEIGHTED_THRESHOLD_POLICY_ADDRESS || "CBYDQ5XUBP7G24FI3LLGLW56QZCIEUSVRPX7FVOUCKHJQQ6DTF6BQGBZ",
  },
];

type LogEntry = {
  message: string;
  type: "info" | "success" | "error";
  timestamp: Date;
};

function App() {
  const [kit, setKit] = useState<SmartAccountKit | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [contractId, setContractId] = useState<string | null>(null);
  const [pendingCredentials, setPendingCredentials] = useState<StoredCredential[]>([]);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState<string | null>(null);
  const [configValid, setConfigValid] = useState(false);
  const [balance, setBalance] = useState<string | null>(null);
  const [autoConnectAttempted, setAutoConnectAttempted] = useState(false);

  // Form state
  const [userName, setUserName] = useState("");
  const [transferTo, setTransferTo] = useState("");
  const [transferAmount, setTransferAmount] = useState("10");

  // Editable config
  const [accountWasmHash, setAccountWasmHash] = useState(CONFIG.accountWasmHash);
  const [webauthnVerifier, setWebauthnVerifier] = useState(CONFIG.webauthnVerifierAddress);

  // Modal state
  const [ruleBuilderOpen, setRuleBuilderOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<ContextRule | null>(null);
  const [contextRulesKey, setContextRulesKey] = useState(0); // For forcing re-fetch

  // SignerPicker state for multi-signer transactions
  const [signerPickerOpen, setSignerPickerOpen] = useState(false);
  const [pendingTransfer, setPendingTransfer] = useState<{
    recipient: string;
    amount: number;
  } | null>(null);

  // All signers from on-chain context rules
  const [allSigners, setAllSigners] = useState<Signer[]>([]);
  const [activeSigner, setActiveSigner] = useState<Signer | null>(null);
  const [credentialId, setCredentialIdState] = useState<string | null>(null);

  // External wallet connection - managed by SDK
  const [connectedWallets, setConnectedWallets] = useState<ConnectedWallet[]>([]);

  // Discovered contracts from indexer (for account selection)
  const [discoveredContracts, setDiscoveredContracts] = useState<IndexedContractSummary[]>([]);
  const [showContractPicker, setShowContractPicker] = useState(false);
  const [pendingCredentialForPicker, setPendingCredentialForPicker] = useState<string | null>(null);

  // Refresh connected wallets from SDK (includes both wallet and keypair signers)
  const refreshConnectedWallets = useCallback(() => {
    if (kit) {
      const allSigners = kit.externalSigners.getAll();
      const wallets = allSigners.map(s => ({
        address: s.address,
        walletId: s.walletId || (s.type === "keypair" ? "keypair" : "unknown"),
        walletName: s.walletName || (s.type === "keypair" ? "Secret Key" : "Unknown Wallet"),
      }));
      setConnectedWallets(wallets);
    }
  }, [kit]);

  // Connect wallet via SDK
  const connectWallet = useCallback(async (): Promise<ConnectedWallet | null> => {
    if (!kit) return null;
    const result = await kit.externalSigners.addFromWallet();
    refreshConnectedWallets();
    return result;
  }, [kit, refreshConnectedWallets]);

  // Disconnect all wallets via SDK
  const disconnectWallet = useCallback(async () => {
    if (!kit) return;
    await kit.externalSigners.removeAll();
    setConnectedWallets([]);
  }, [kit]);

  // Disconnect specific wallet via SDK
  const disconnectWalletByAddress = useCallback((address: string) => {
    if (!kit) return;
    kit.externalSigners.remove(address);
    refreshConnectedWallets();
  }, [kit, refreshConnectedWallets]);

  const log = useCallback(
    (message: string, type: LogEntry["type"] = "info") => {
      setLogs((prev) => [
        { message, type, timestamp: new Date() },
        ...prev.slice(0, 49),
      ]);
    },
    []
  );

  // Add signer from secret key (for manually imported G-addresses)
  const addFromSecret = useCallback((secretKey: string): { address: string } | null => {
    if (!kit) return null;
    try {
      const result = kit.externalSigners.addFromSecret(secretKey);
      refreshConnectedWallets();
      log(`Added secret key signer: ${result.address.slice(0, 10)}...`, "success");
      return result;
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to add secret key";
      log(`Failed to add secret key: ${message}`, "error");
      throw err;
    }
  }, [kit, refreshConnectedWallets, log]);

  // Fetch wallet balance
  const fetchBalance = useCallback(async (walletContractId: string) => {
    try {
      const server = new rpc.Server(CONFIG.rpcUrl);
      const result = await server.getSACBalance(
        walletContractId,
        Asset.native(),
        CONFIG.networkPassphrase
      );
      if (result.balanceEntry) {
        // Convert from stroops to XLM
        const xlmBalance = (Number(result.balanceEntry.amount) / 10_000_000).toFixed(2);
        setBalance(xlmBalance);
      } else {
        setBalance("0.00");
      }
    } catch (error) {
      console.warn("Failed to fetch balance:", error);
      setBalance(null);
    }
  }, []);

  // Fetch all unique signers from on-chain context rules using SDK
  const fetchAllSigners = useCallback(async (kitInstance: SmartAccountKit, activeCredId: string | null) => {
    try {
      // Use SDK's multiSigners to get deduplicated signers from all rules
      const uniqueSigners = await kitInstance.multiSigners.getAvailableSigners();
      setAllSigners(uniqueSigners);

      // Find the active signer based on credential ID
      if (activeCredId) {
        const active = uniqueSigners.find((s) => {
          const credId = getCredentialIdFromSigner(s);
          return credId === activeCredId;
        });
        setActiveSigner(active || null);
      } else {
        setActiveSigner(null);
      }

      return uniqueSigners;
    } catch (error) {
      console.warn("Failed to fetch signers:", error);
      return [];
    }
  }, []);

  // Initialize kit when config changes
  useEffect(() => {
    if (!accountWasmHash || !webauthnVerifier) {
      setConfigValid(false);
      return;
    }

    const initKit = async () => {
      try {
        // Create and initialize the wallet adapter
        const walletAdapter = new StellarWalletsKitAdapter({
          network: CONFIG.networkPassphrase,
        });
        await walletAdapter.init();

        const newKit = new SmartAccountKit({
          rpcUrl: CONFIG.rpcUrl,
          networkPassphrase: CONFIG.networkPassphrase,
          accountWasmHash,
          webauthnVerifierAddress: webauthnVerifier,
          storage: new IndexedDBStorage(),
          rpName: "Smart Account Kit Demo",
          externalWallet: walletAdapter,
          // Enable Relayer fee sponsoring if URL is configured
          relayerUrl: CONFIG.relayerUrl || undefined,
        });
        setKit(newKit);
        setConfigValid(true);

        // Reset connection state when kit is re-initialized
        setIsConnected(false);
        setContractId(null);
        setAutoConnectAttempted(false);

        log("SDK initialized with provided config", "success");

        // Log fee sponsoring status
        if (newKit.relayer) {
          log("Relayer fee sponsoring enabled", "success");
        }

        // Sync credentials - clean up any that are already deployed,
        // keep pending ones for retry
        const { deployed } = await newKit.credentials.syncAll();
        if (deployed > 0) {
          log(`Cleaned up ${deployed} deployed credential(s)`, "info");
        }
        // Load pending credentials for display
        const pendingCreds = await newKit.credentials.getPending();
        setPendingCredentials(pendingCreds);
        if (pendingCreds.length > 0) {
          log(`Found ${pendingCreds.length} pending credential(s)`, "info");
        }
      } catch (error) {
        log(`Failed to initialize SDK: ${error}`, "error");
        setConfigValid(false);
      }
    };

    initKit();
  }, [accountWasmHash, webauthnVerifier, log]);

  // Auto-connect to stored session (silent - no passkey prompt)
  useEffect(() => {
    if (!kit || !configValid || isConnected || autoConnectAttempted) {
      return;
    }

    setAutoConnectAttempted(true);

    const autoConnect = async () => {
      // Silent restore - returns null if no stored session
      const result = await kit.connectWallet();

      if (result) {
        log(`Session restored: ${result.contractId.slice(0, 10)}...`, "success");
        setContractId(result.contractId);
        setCredentialIdState(result.credentialId);
        setIsConnected(true);
        fetchBalance(result.contractId);
        fetchAllSigners(kit, result.credentialId);
      }
    };

    autoConnect().catch((error) => {
      log(`Auto-connect failed: ${error}`, "error");
    });
  }, [kit, configValid, isConnected, autoConnectAttempted, log, fetchBalance, fetchAllSigners]);

  const handleCreateWallet = async () => {
    if (!kit) return;

    const name = userName.trim() || "Demo User";
    setLoading("Creating wallet...");
    log(`Creating wallet for "${name}"...`);

    try {
      const result = await kit.createWallet("Smart Account Demo", name, {
        autoSubmit: true,
      });

      log(`Passkey created: ${result.credentialId.slice(0, 20)}...`, "success");
      log(`Contract address: ${result.contractId}`, "success");

      if (result.submitResult?.success) {
        log("Wallet deployed successfully!", "success");
        log(`Transaction: ${result.submitResult.hash.slice(0, 20)}...`, "success");
        setContractId(result.contractId);
        setCredentialIdState(result.credentialId);
        setIsConnected(true);
        fetchBalance(result.contractId);
        fetchAllSigners(kit, result.credentialId);
        // Session is automatically saved by the kit
      } else if (result.submitResult) {
        log(`Deployment failed: ${result.submitResult.error}`, "error");
        // Refresh pending credentials to show the failed one
        setPendingCredentials(await kit.credentials.getPending());
      }
    } catch (error) {
      log(`Failed to create wallet: ${error}`, "error");
      // Refresh pending credentials in case a credential was created
      setPendingCredentials(await kit.credentials.getPending());
    } finally {
      setLoading(null);
    }
  };

  const handleConnectWallet = async () => {
    if (!kit) return;

    setLoading("Connecting...");
    log("Prompting for passkey selection...");

    try {
      // Step 1: Authenticate with passkey to get credential ID (without connecting to a contract)
      const { credentialId } = await kit.authenticatePasskey();
      log(`Authenticated with credential: ${credentialId.slice(0, 20)}...`, "success");

      // Step 2: Try to discover contracts via indexer
      const contracts = await kit.discoverContractsByCredential(credentialId);

      if (contracts && contracts.length > 1) {
        // Multiple contracts found - show picker
        log(`Found ${contracts.length} smart accounts for this passkey`, "info");
        setDiscoveredContracts(contracts);
        setPendingCredentialForPicker(credentialId);
        setShowContractPicker(true);
        setLoading(null);
        return;
      } else if (contracts && contracts.length === 1) {
        // Single contract - connect directly
        log(`Found 1 smart account via indexer, connecting...`, "info");
        const result = await kit.connectWallet({
          contractId: contracts[0].contract_id,
          credentialId,
        });

        if (result) {
          log(`Contract ID: ${result.contractId}`, "success");
          setContractId(result.contractId);
          setCredentialIdState(result.credentialId);
          setIsConnected(true);
          fetchBalance(result.contractId);
          fetchAllSigners(kit, result.credentialId);
        }
        return;
      }

      // Step 3: No indexed contracts found - fall back to derived contract ID
      log(`No indexed contracts found, trying derived contract ID...`, "info");
      const result = await kit.connectWallet({
        credentialId,
      });

      if (result) {
        log(`Contract ID: ${result.contractId}`, "success");
        setContractId(result.contractId);
        setCredentialIdState(result.credentialId);
        setIsConnected(true);
        fetchBalance(result.contractId);
        fetchAllSigners(kit, result.credentialId);
      }
    } catch (error) {
      log(`Failed to connect: ${error}`, "error");
    } finally {
      setLoading(null);
    }
  };

  // Handle contract selection from picker
  const handleContractSelect = async (selectedContract: IndexedContractSummary) => {
    if (!kit || !pendingCredentialForPicker) return;

    setShowContractPicker(false);
    setLoading("Connecting to selected account...");
    log(`Connecting to contract: ${selectedContract.contract_id.slice(0, 10)}...`);

    try {
      // Connect to the selected contract by providing the contract ID
      const result = await kit.connectWallet({
        contractId: selectedContract.contract_id,
        credentialId: pendingCredentialForPicker,
      });

      if (result) {
        log(`Connected to: ${result.contractId}`, "success");
        setContractId(result.contractId);
        setCredentialIdState(result.credentialId);
        setIsConnected(true);
        fetchBalance(result.contractId);
        fetchAllSigners(kit, result.credentialId);
      }
    } catch (error) {
      log(`Failed to connect: ${error}`, "error");
    } finally {
      setLoading(null);
      setPendingCredentialForPicker(null);
      setDiscoveredContracts([]);
    }
  };

  const handleDisconnect = async () => {
    if (!kit) return;

    await kit.disconnect();
    setContractId(null);
    setBalance(null);
    setCredentialIdState(null);
    setIsConnected(false);
    setAllSigners([]);
    setActiveSigner(null);
    // Session is automatically cleared by the kit
    log("Disconnected from wallet");
  };

  const handleTransfer = async () => {
    if (!kit || !isConnected || !contractId) return;

    const recipient = transferTo.trim();
    const amount = parseFloat(transferAmount.trim());

    // Validate inputs using SDK utilities
    try {
      validateAddress(recipient, "recipient address");
      validateAmount(amount, "transfer amount");
    } catch (error) {
      log(error instanceof Error ? error.message : "Validation failed", "error");
      return;
    }

    // Check if we have multiple signers available
    // If so, show the signer picker to let user choose
    if (allSigners.length > 1) {
      log("Multiple signers available - select signers for this transaction");
      setPendingTransfer({ recipient, amount });
      setSignerPickerOpen(true);
      return;
    }

    // Single signer - use the standard flow
    setLoading("Building transfer...");
    log(`Transferring ${amount} XLM to ${recipient.slice(0, 10)}...`);
    log(`From smart wallet: ${contractId}`, "info");

    try {
      // Use the kit's transfer helper - handles simulation, signing, and submission
      const result = await kit.transfer(
        CONFIG.nativeTokenContract,
        recipient,
        amount
      );

      if (result.success) {
        log(`Transfer successful! Sent ${amount} XLM to ${recipient.slice(0, 10)}...`, "success");
        log(`Transaction: ${result.hash.slice(0, 20)}...`, "success");
        fetchBalance(contractId);
      } else {
        throw new Error(result.error || "Transfer failed");
      }
    } catch (error) {
      log(`Transfer failed: ${error}`, "error");
    } finally {
      setLoading(null);
    }
  };

  // Handle signer selection confirmation for multi-signer transactions
  const handleSignerConfirm = async (selectedSigners: SelectedSigner[]) => {
    if (!kit || !pendingTransfer || !contractId) return;

    const { recipient, amount } = pendingTransfer;
    setPendingTransfer(null);

    setLoading("Building multi-signer transfer...");
    log(`Transferring ${amount} XLM with ${selectedSigners.length} signer(s)`);
    log(`From smart wallet: ${contractId}`, "info");

    try {
      // Use SDK's built-in multi-signer transfer
      const result = await kit.multiSigners.transfer(
        CONFIG.nativeTokenContract,
        recipient,
        amount,
        selectedSigners,
        {
          onLog: log,
        }
      );

      if (result.success) {
        log(`Transfer successful! Sent ${amount} XLM to ${recipient.slice(0, 10)}...`, "success");
        log(`Transaction: ${result.hash.slice(0, 20)}...`, "success");
        fetchBalance(contractId);
      } else {
        throw new Error(result.error || "Transfer failed");
      }
    } catch (error) {
      log(`Multi-signer transfer failed: ${error}`, "error");
    } finally {
      setLoading(null);
    }
  };

  const handleFundWallet = async () => {
    if (!kit || !contractId) return;

    setLoading("Funding wallet...");
    log("Funding wallet via Friendbot and transfer...");

    try {
      // Use the kit's fundWallet helper - transfers full balance minus 5 XLM reserve
      const result = await kit.fundWallet(CONFIG.nativeTokenContract);

      if (result.success) {
        const amount = result.amount?.toFixed(2) ?? "?";
        log(`Funded smart wallet with ${amount} XLM!`, "success");
        if (result.hash) {
          log(`Transaction: ${result.hash.slice(0, 20)}...`, "success");
        }
        fetchBalance(contractId);
      } else {
        throw new Error(result.error || "Funding failed");
      }
    } catch (error) {
      log(`Funding failed: ${error}`, "error");
    } finally {
      setLoading(null);
    }
  };

  const handleDeployPending = async (credential: StoredCredential) => {
    if (!kit) return;

    setLoading(`Deploying ${credential.credentialId.slice(0, 10)}...`);
    log(`Deploying pending credential: ${credential.credentialId.slice(0, 20)}...`);

    try {
      const result = await kit.credentials.deploy(credential.credentialId, {
        autoSubmit: true,
      });

      if (result.submitResult?.success) {
        log("Wallet deployed successfully!", "success");
        log(`Transaction: ${result.submitResult.hash.slice(0, 20)}...`, "success");
        setContractId(result.contractId);
        setCredentialIdState(credential.credentialId);
        setIsConnected(true);
        fetchBalance(result.contractId);
        fetchAllSigners(kit, credential.credentialId);
        // Session is automatically saved by the kit
        // Refresh pending list
        setPendingCredentials(await kit.credentials.getPending());
      } else if (result.submitResult) {
        log(`Deployment failed: ${result.submitResult.error}`, "error");
        setPendingCredentials(await kit.credentials.getPending());
      }
    } catch (error) {
      log(`Failed to deploy: ${error}`, "error");
      setPendingCredentials(await kit.credentials.getPending());
    } finally {
      setLoading(null);
    }
  };

  const handleDeletePending = async (credential: StoredCredential) => {
    if (!kit) return;

    log(`Removing pending credential: ${credential.credentialId.slice(0, 20)}...`);

    try {
      await kit.credentials.delete(credential.credentialId);
      log("Credential removed from storage", "success");
      setPendingCredentials(await kit.credentials.getPending());
    } catch (error) {
      log(`Failed to remove: ${error}`, "error");
    }
  };

  // Modal handlers
  const handleAddRule = () => {
    setEditingRule(null);
    setRuleBuilderOpen(true);
  };

  const handleEditRule = (rule: ContextRule) => {
    setEditingRule(rule);
    setRuleBuilderOpen(true);
  };

  const handleRuleBuilderClose = async () => {
    setRuleBuilderOpen(false);
    setEditingRule(null);
    // Refresh pending credentials (in case one was created but not deployed)
    if (kit) {
      setPendingCredentials(await kit.credentials.getPending());
    }
  };

  const handleRuleBuilderSuccess = async () => {
    // Force re-fetch of context rules and signers
    setContextRulesKey((prev) => prev + 1);
    if (kit) {
      fetchAllSigners(kit, credentialId);
      // Refresh pending credentials (some may have been deployed)
      setPendingCredentials(await kit.credentials.getPending());
    }
  };

  return (
    <div className="container">
      <header>
        <h1>Smart Account Kit Demo</h1>
        <h2>Test WebAuthn passkey wallets on Stellar/Soroban</h2>
      </header>

      {/* Configuration */}
      <div className="card">
        <h3>Configuration</h3>
        <div className="form-group">
          <label>Smart Account WASM Hash</label>
          <input
            type="text"
            value={accountWasmHash}
            onChange={(e) => setAccountWasmHash(e.target.value)}
            placeholder="Enter deployed WASM hash..."
          />
        </div>
        <div className="form-group">
          <label>WebAuthn Verifier Address</label>
          <input
            type="text"
            value={webauthnVerifier}
            onChange={(e) => setWebauthnVerifier(e.target.value)}
            placeholder="C..."
          />
        </div>

        {/* Policy contracts - informational */}
        <details style={{ marginTop: "12px" }}>
          <summary style={{ cursor: "pointer", color: "#71717a", fontSize: "0.9rem" }}>
            Available Policy Contracts
          </summary>
          <div style={{ marginTop: "12px" }}>
            <p style={{ fontSize: "0.85rem", color: "#71717a", marginBottom: "12px" }}>
              These policy contracts are deployed to testnet and can be attached to context rules.
              Policies define additional conditions that must be met for a transaction to be authorized.
            </p>

            <div className="policy-list">
              {KNOWN_POLICIES.map((policy) => (
                <div key={policy.address} className="policy-item">
                  <div className="policy-info">
                    <span className="policy-name">{policy.name}</span>
                    <span className="policy-description">{policy.description}</span>
                    <code className="policy-address">{policy.address}</code>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </details>

        <div style={{ display: "flex", gap: "12px", alignItems: "center", marginTop: "16px" }}>
          <span className="network-badge">Testnet</span>
          <span
            className={`status ${configValid ? "connected" : "disconnected"}`}
          >
            {configValid ? "Config Valid" : "Missing Config"}
          </span>
          {kit?.relayer && (
            <span className="status connected" title="Fee sponsoring via Relayer">
              Relayer
            </span>
          )}
        </div>
      </div>

      {/* External Wallet Connection */}
      <div className="card">
        <div className="section-header">
          <h3>External Wallets</h3>
          <span className={`status ${connectedWallets.length > 0 ? "connected" : "disconnected"}`}>
            {connectedWallets.length > 0 ? `${connectedWallets.length} Connected` : "None Connected"}
          </span>
        </div>
        <p className="panel-description">
          Connect external Stellar wallets (Freighter, Lobstr, Albedo, etc.) to sign transactions
          with Delegated signers. This enables multi-signer scenarios combining passkeys
          with traditional Stellar accounts. You can connect multiple wallets.
        </p>

        {connectedWallets.length > 0 && (
          <div className="connected-wallets-list-section">
            {connectedWallets.map((wallet) => (
              <div key={wallet.address} className="connected-wallet-banner">
                <div className="connected-wallet-info">
                  <div className="wallet-details">
                    <span className="wallet-name">{wallet.walletName}</span>
                    <span className="wallet-address">
                      {wallet.address.slice(0, 8)}...{wallet.address.slice(-4)}
                    </span>
                  </div>
                </div>
                <button
                  className="secondary disconnect-btn small"
                  onClick={async () => {
                    disconnectWalletByAddress(wallet.address);
                    log(`Disconnected ${wallet.walletName}: ${wallet.address.slice(0, 10)}...`);
                  }}
                  title="Disconnect this wallet"
                >
                  ×
                </button>
              </div>
            ))}
          </div>
        )}

        <div className="button-group" style={{ marginTop: connectedWallets.length > 0 ? "12px" : "0" }}>
          <button
            className="secondary"
            onClick={async () => {
              log("Opening wallet connection modal...");
              const result = await connectWallet();
              if (result) {
                log(`Connected to ${result.walletName}: ${result.address.slice(0, 10)}...`, "success");
              }
            }}
          >
            {connectedWallets.length > 0 ? "+ Connect Another Wallet" : "Connect External Wallet"}
          </button>
          {connectedWallets.length > 0 && (
            <button
              className="secondary danger"
              onClick={async () => {
                await disconnectWallet();
                log("All external wallets disconnected");
              }}
            >
              Disconnect All
            </button>
          )}
        </div>
      </div>

      {/* Pending Credentials (shown when not connected) */}
      {pendingCredentials.length > 0 && !isConnected && (
        <div className="card pending-credentials-card">
          <h3>Pending Credentials</h3>
          <p className="pending-description">
            These passkeys were created but wallet deployment failed or is incomplete.
            Deploy to create a wallet, or delete to remove from tracking.
          </p>
          <div className="credentials-list">
            {pendingCredentials.map((cred) => (
              <div key={cred.credentialId} className="credential-item pending">
                <div className="credential-info">
                  <div className="nickname">
                    {cred.nickname || "Unnamed"}
                    <span className={`status-badge ${cred.deploymentStatus}`}>
                      {cred.deploymentStatus === "pending" ? "Pending" : "Failed"}
                    </span>
                  </div>
                  <div className="id">{cred.credentialId}</div>
                  {cred.deploymentError && (
                    <div className="error-text">{cred.deploymentError}</div>
                  )}
                  <div className="credential-date">
                    Created: {new Date(cred.createdAt).toLocaleDateString()}
                  </div>
                </div>
                <div className="credential-actions">
                  <button
                    className="small"
                    onClick={() => handleDeployPending(cred)}
                    disabled={loading !== null}
                  >
                    {loading === `Deploying ${cred.credentialId.slice(0, 10)}...` ? (
                      <span className="spinner" />
                    ) : (
                      "Deploy"
                    )}
                  </button>
                  <button
                    className="small danger"
                    onClick={() => handleDeletePending(cred)}
                    disabled={loading !== null}
                  >
                    Delete
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Wallet Status */}
      <div className="card">
        <div className="section-header">
          <h3>Wallet</h3>
          <span className={`status ${isConnected ? "connected" : "disconnected"}`}>
            {isConnected ? "Connected" : "Not Connected"}
          </span>
        </div>

        {isConnected && contractId && (
          <div className="wallet-info">
            <div className="info-box">
              <div className="label">Contract Address</div>
              <div className="value">{contractId}</div>
            </div>
            <div className="wallet-info-row">
              <div className="balance-display">
                <div className="balance-label">Balance</div>
                <div className="balance-value">
                  {balance !== null ? `${balance} XLM` : "—"}
                </div>
              </div>
              <ActiveSignerDisplay
                credentialId={credentialId}
                activeSigner={activeSigner}
              />
            </div>
          </div>
        )}

        <div className="button-group" style={{ marginTop: "16px" }}>
          {!isConnected ? (
            <>
              <div className="form-group" style={{ flex: 1, marginBottom: 0 }}>
                <input
                  type="text"
                  value={userName}
                  onChange={(e) => setUserName(e.target.value)}
                  placeholder="Enter username (optional)"
                />
              </div>
              <button
                onClick={handleCreateWallet}
                disabled={loading !== null || !configValid}
              >
                {loading === "Creating wallet..." ? (
                  <span className="spinner" />
                ) : (
                  "Create Wallet"
                )}
              </button>
              <button
                className="secondary"
                onClick={handleConnectWallet}
                disabled={loading !== null || !configValid}
              >
                {loading === "Connecting..." ? (
                  <span className="spinner" />
                ) : (
                  "Connect Existing"
                )}
              </button>
            </>
          ) : (
            <>
              <button className="secondary" onClick={handleDisconnect}>
                Disconnect
              </button>
              <button
                onClick={handleFundWallet}
                disabled={loading !== null}
              >
                {loading === "Funding wallet..." ? (
                  <span className="spinner" />
                ) : (
                  "Fund Wallet (Testnet)"
                )}
              </button>
            </>
          )}
        </div>
      </div>

      {/* Context Rules Panel (on-chain rules) */}
      {isConnected && kit && (
        <ContextRulesPanel
          key={contextRulesKey}
          kit={kit}
          isConnected={isConnected}
          onLog={log}
          onAddRule={handleAddRule}
          onEditRule={handleEditRule}
          connectedWallets={connectedWallets}
          connectWallet={connectWallet}
        />
      )}

      {/* Transfer */}
      {isConnected && (
        <div className="card">
          <h3>Token Transfer (XLM)</h3>
          <div className="form-group">
            <label>Recipient Address</label>
            <input
              type="text"
              value={transferTo}
              onChange={(e) => setTransferTo(e.target.value)}
              placeholder="G... or C..."
            />
          </div>
          <div className="form-group">
            <label>Amount (XLM)</label>
            <input
              type="text"
              value={transferAmount}
              onChange={(e) => setTransferAmount(e.target.value)}
              placeholder="10"
            />
          </div>
          <div className="button-group">
            <button
              onClick={handleTransfer}
              disabled={loading !== null || !transferTo}
            >
              {loading === "Building transfer..." ? (
                <span className="spinner" />
              ) : (
                "Send Transfer"
              )}
            </button>
          </div>
        </div>
      )}

      {/* Activity Log */}
      <div className="card">
        <h3>Activity Log</h3>
        <div className="log-box">
          {logs.length === 0 ? (
            <div className="log-entry">No activity yet...</div>
          ) : (
            logs.map((entry, i) => (
              <div key={i} className={`log-entry ${entry.type}`}>
                [{entry.timestamp.toLocaleTimeString()}] {entry.message}
              </div>
            ))
          )}
        </div>
      </div>

      {/* Context Rule Builder Modal */}
      {kit && (
        <ContextRuleBuilder
          kit={kit}
          isOpen={ruleBuilderOpen}
          onClose={handleRuleBuilderClose}
          onLog={log}
          onSuccess={handleRuleBuilderSuccess}
          editingRule={editingRule}
          availablePolicies={KNOWN_POLICIES}
          webauthnVerifierAddress={webauthnVerifier}
          activeCredentialId={credentialId}
          existingSigners={allSigners}
          pendingCredentials={pendingCredentials}
          connectedWallets={connectedWallets}
          connectWallet={connectWallet}
          disconnectWalletByAddress={disconnectWalletByAddress}
        />
      )}

      {/* Signer Picker Modal for multi-signer transactions */}
      <SignerPicker
        isOpen={signerPickerOpen}
        onClose={() => {
          setSignerPickerOpen(false);
          setPendingTransfer(null);
        }}
        availableSigners={allSigners}
        activeCredentialId={credentialId}
        onConfirm={handleSignerConfirm}
        title="Select Signers for Transfer"
        description={
          pendingTransfer
            ? `Choose which signers to use for transferring ${pendingTransfer.amount} XLM to ${pendingTransfer.recipient.slice(0, 10)}...`
            : "Choose which signers to use for this transaction."
        }
        connectedWallets={connectedWallets}
        connectWallet={connectWallet}
        disconnectWalletByAddress={disconnectWalletByAddress}
        addFromSecret={addFromSecret}
      />

      {/* Contract Picker Modal for multi-contract passkeys */}
      {showContractPicker && (
        <div className="modal-overlay" onClick={() => {
          setShowContractPicker(false);
          setPendingCredentialForPicker(null);
          setDiscoveredContracts([]);
        }}>
          <div className="modal-content contract-picker-modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Select Smart Account</h3>
              <button
                className="close-btn"
                onClick={() => {
                  setShowContractPicker(false);
                  setPendingCredentialForPicker(null);
                  setDiscoveredContracts([]);
                }}
              >
                ×
              </button>
            </div>
            <p className="modal-description">
              Your passkey is registered with {discoveredContracts.length} smart accounts.
              Select which one to connect to:
            </p>
            <div className="contract-list">
              {discoveredContracts.map((contract) => (
                <div
                  key={contract.contract_id}
                  className="contract-option"
                  onClick={() => handleContractSelect(contract)}
                >
                  <div className="contract-option-header">
                    <code className="contract-address">
                      {contract.contract_id.slice(0, 8)}...{contract.contract_id.slice(-4)}
                    </code>
                  </div>
                  <div className="contract-option-stats">
                    <span className="stat">
                      {contract.context_rule_count} rule{contract.context_rule_count !== 1 ? 's' : ''}
                    </span>
                    <span className="stat">
                      {contract.external_signer_count + contract.delegated_signer_count} signer{(contract.external_signer_count + contract.delegated_signer_count) !== 1 ? 's' : ''}
                    </span>
                    <span className="stat ledger">
                      Ledger {contract.last_seen_ledger}
                    </span>
                  </div>
                </div>
              ))}
            </div>
            <div className="modal-footer">
              <button
                className="secondary"
                onClick={() => {
                  setShowContractPicker(false);
                  setPendingCredentialForPicker(null);
                  setDiscoveredContracts([]);
                }}
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
