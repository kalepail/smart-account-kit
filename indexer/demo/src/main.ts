/**
 * Smart Account Indexer Demo
 *
 * This demo shows how to:
 * 1. Authenticate with a passkey
 * 2. Extract the public key from the authentication response
 * 3. Query the indexer for associated smart account contracts
 * 4. Display contracts with balances and activity
 * 5. Allow user to select which contract to connect to
 */

import { startAuthentication } from "@simplewebauthn/browser";
import { rpc, xdr, Address, scValToNative } from "@stellar/stellar-sdk";

// Types
interface SmartAccountInfo {
  contractId: string;
  contextRuleCount: number;
  externalSignerCount: number;
  delegatedSignerCount: number;
  nativeSignerCount: number;
  firstSeenLedger: number;
  lastSeenLedger: number;
  contextRuleIds: number[];
  // Enriched data
  contractExists?: boolean;
}

interface SignerInfo {
  signer_type: string;
  signer_address: string | null;
  credential_id: string | null;
}

interface PolicyInfo {
  policy_address: string;
  install_params: any;
}

interface ContextRuleInfo {
  context_rule_id: number;
  signers: SignerInfo[];
  policies: PolicyInfo[];
}

interface ContractDetails {
  contractId: string;
  summary: SmartAccountInfo;
  contextRules: ContextRuleInfo[];
}

// State
let selectedContract: string | null = null;
let discoveredContracts: SmartAccountInfo[] = [];
let currentCredentialId: string | null = null;
let currentSignerAddress: string | null = null;

// DOM Elements
const authBtn = document.getElementById("auth-btn") as HTMLButtonElement;
const lookupBtn = document.getElementById("lookup-btn") as HTMLButtonElement;
const addressLookupBtn = document.getElementById("address-lookup-btn") as HTMLButtonElement;
const backBtn = document.getElementById("back-btn") as HTMLButtonElement;
const statusEl = document.getElementById("status") as HTMLDivElement;
const contractsList = document.getElementById("contracts-list") as HTMLDivElement;
const contractDetailsSection = document.getElementById("contract-details-section") as HTMLDivElement;
const contractDetailsEl = document.getElementById("contract-details") as HTMLDivElement;
const publicKeyInput = document.getElementById("public-key") as HTMLInputElement;
const stellarAddressInput = document.getElementById("stellar-address") as HTMLInputElement;
const indexerUrlInput = document.getElementById("indexer-url") as HTMLInputElement;
const rpcUrlInput = document.getElementById("rpc-url") as HTMLInputElement;

// Set default values from environment variables (with fallbacks)
indexerUrlInput.value = import.meta.env.VITE_INDEXER_URL || "https://smart-account-indexer.sdf-ecosystem.workers.dev";
rpcUrlInput.value = import.meta.env.VITE_RPC_URL || "https://soroban-testnet.stellar.org";

// ============================================================================
// Utility Functions
// ============================================================================

function showStatus(message: string, type: "success" | "error" | "info") {
  statusEl.textContent = message;
  statusEl.className = type;
  statusEl.style.display = "block";
}

function hideStatus() {
  statusEl.style.display = "none";
}

function truncateContractId(contractId: string): string {
  return `${contractId.slice(0, 8)}...${contractId.slice(-8)}`;
}

// ============================================================================
// Policy RPC Loading
// ============================================================================

/**
 * Build a ledger key for a policy's storage entry.
 * Policy contracts store data with key: AccountContext(smartAccountAddress, contextRuleId)
 */
function buildPolicyStorageKey(
  policyAddress: string,
  smartAccountAddress: string,
  contextRuleId: number
): xdr.LedgerKey {
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
 * Batch load policy params from RPC for all policies across all context rules.
 * Returns a Map keyed by "contextRuleId:policyAddress" with the parsed params.
 */
async function loadPolicyParamsFromRpc(
  contractId: string,
  contextRules: ContextRuleInfo[]
): Promise<Map<string, any>> {
  const rpcUrl = rpcUrlInput.value;
  const server = new rpc.Server(rpcUrl);
  const paramsMap = new Map<string, any>();

  // Collect all policy keys we need to fetch
  const keysToFetch: { key: xdr.LedgerKey; mapKey: string }[] = [];

  for (const rule of contextRules) {
    if (!rule.policies) continue;
    for (const policy of rule.policies) {
      const ledgerKey = buildPolicyStorageKey(
        policy.policy_address,
        contractId,
        rule.context_rule_id
      );
      keysToFetch.push({
        key: ledgerKey,
        mapKey: `${rule.context_rule_id}:${policy.policy_address}`,
      });
    }
  }

  if (keysToFetch.length === 0) {
    return paramsMap;
  }

  try {
    // Batch fetch all ledger entries in one RPC call
    const response = await server.getLedgerEntries(...keysToFetch.map((k) => k.key));

    if (response.entries) {
      for (let i = 0; i < response.entries.length; i++) {
        const entry = response.entries[i];
        if (entry) {
          try {
            const dataEntry = entry.val.contractData();
            const value = scValToNative(dataEntry.val());
            // Find the corresponding mapKey by matching the ledger key
            // Since entries come back in same order as keys, use index
            const mapKey = keysToFetch[i]?.mapKey;
            if (mapKey) {
              paramsMap.set(mapKey, value);
            }
          } catch (parseError) {
            console.warn("Failed to parse policy entry:", parseError);
          }
        }
      }
    }
  } catch (error) {
    console.warn("Failed to fetch policy params from RPC:", error);
  }

  return paramsMap;
}

/**
 * Format policy params for display based on the value structure
 */
function formatPolicyParamsFromRpc(params: any): string {
  if (!params) return "";

  // Handle different policy value structures
  if (typeof params === "number" || typeof params === "bigint") {
    // Simple threshold policy (just a number)
    return `threshold: ${params}`;
  }

  if (typeof params === "object") {
    const parts: string[] = [];

    // Spending limit policy
    if (params.spending_limit !== undefined) {
      const limitXlm = Number(params.spending_limit) / 10_000_000;
      parts.push(`limit: ${limitXlm} XLM`);
    }
    if (params.period_ledgers !== undefined) {
      const days = Math.round(Number(params.period_ledgers) / (17280)); // ~17280 ledgers per day
      parts.push(`period: ${days} day${days !== 1 ? "s" : ""}`);
    }

    // Weighted threshold policy
    if (params.threshold !== undefined && !params.spending_limit) {
      parts.push(`threshold: ${params.threshold}`);
    }

    // Generic key-value pairs
    if (parts.length === 0) {
      for (const [key, val] of Object.entries(params)) {
        if (val !== undefined && val !== null) {
          parts.push(`${key}: ${val}`);
        }
      }
    }

    return parts.join(", ");
  }

  return String(params);
}

// ============================================================================
// Indexer Client
// ============================================================================

async function lookupContractsByCredentialId(
  credentialId: string
): Promise<SmartAccountInfo[]> {
  const indexerUrl = indexerUrlInput.value;
  const normalizedKey = credentialId.toLowerCase().replace(/^0x/, "");

  const response = await fetch(`${indexerUrl}/api/lookup/${normalizedKey}`);

  if (!response.ok) {
    throw new Error(`Indexer lookup failed: ${response.statusText}`);
  }

  const data = await response.json();

  return data.contracts.map((c: any) => ({
    contractId: c.contract_id,
    contextRuleCount: parseInt(c.context_rule_count),
    externalSignerCount: parseInt(c.external_signer_count),
    delegatedSignerCount: parseInt(c.delegated_signer_count),
    nativeSignerCount: parseInt(c.native_signer_count || "0"),
    firstSeenLedger: parseInt(c.first_seen_ledger),
    lastSeenLedger: parseInt(c.last_seen_ledger),
    contextRuleIds: c.context_rule_ids,
  }));
}

async function lookupContractsByAddress(
  signerAddress: string
): Promise<SmartAccountInfo[]> {
  const indexerUrl = indexerUrlInput.value;

  const response = await fetch(`${indexerUrl}/api/lookup/address/${signerAddress}`);

  if (!response.ok) {
    throw new Error(`Indexer lookup failed: ${response.statusText}`);
  }

  const data = await response.json();

  return data.contracts.map((c: any) => ({
    contractId: c.contract_id,
    contextRuleCount: parseInt(c.context_rule_count),
    externalSignerCount: parseInt(c.external_signer_count),
    delegatedSignerCount: parseInt(c.delegated_signer_count),
    nativeSignerCount: parseInt(c.native_signer_count || "0"),
    firstSeenLedger: parseInt(c.first_seen_ledger),
    lastSeenLedger: parseInt(c.last_seen_ledger),
    contextRuleIds: c.context_rule_ids,
  }));
}

async function getContractDetails(contractId: string): Promise<ContractDetails> {
  const indexerUrl = indexerUrlInput.value;

  const response = await fetch(`${indexerUrl}/api/contract/${contractId}`);

  if (!response.ok) {
    throw new Error(`Failed to fetch contract details: ${response.statusText}`);
  }

  return await response.json();
}

async function enrichWithContractCheck(account: SmartAccountInfo): Promise<SmartAccountInfo> {
  const rpcUrl = rpcUrlInput.value;

  try {
    const server = new rpc.Server(rpcUrl);

    // Build the contract instance ledger key using XDR
    const ledgerKey = xdr.LedgerKey.contractData(
      new xdr.LedgerKeyContractData({
        contract: new Address(account.contractId).toScAddress(),
        key: xdr.ScVal.scvLedgerKeyContractInstance(),
        durability: xdr.ContractDataDurability.persistent(),
      })
    );

    const response = await server.getLedgerEntries(ledgerKey);
    return {
      ...account,
      contractExists: (response.entries?.length ?? 0) > 0,
    };
  } catch (error) {
    console.warn("Failed to check contract:", error);
    return account;
  }
}

// ============================================================================
// UI Rendering
// ============================================================================

function renderContracts(contracts: SmartAccountInfo[]) {
  if (contracts.length === 0) {
    contractsList.innerHTML = `
      <div class="empty-state">
        No contracts found for this credential.
      </div>
    `;
    return;
  }

  // Auto-select first contract if none selected (before rendering so selected class is applied)
  if (contracts.length > 0 && !selectedContract) {
    selectedContract = contracts[0].contractId;
  }

  contractsList.innerHTML = contracts
    .map(
      (contract, index) => {
        const isSelected = selectedContract === contract.contractId;
        return `
      <div class="contract-card ${isSelected ? "selected" : ""}"
           data-contract-id="${contract.contractId}"
           data-index="${index}">
        <div style="display: flex; justify-content: space-between; align-items: flex-start;">
          <div>
            <div class="contract-id">${truncateContractId(contract.contractId)}</div>
            <div style="margin-top: 0.5rem; display: flex; gap: 1rem; flex-wrap: wrap;">
              <span class="activity">${contract.contextRuleCount} context rule${contract.contextRuleCount !== 1 ? 's' : ''}</span>
              <span class="activity">${contract.externalSignerCount + contract.delegatedSignerCount} signer${(contract.externalSignerCount + contract.delegatedSignerCount) !== 1 ? 's' : ''}</span>
            </div>
            <div class="activity" style="margin-top: 0.25rem;">
              Last activity: ledger ${contract.lastSeenLedger.toLocaleString()}
            </div>
          </div>
          ${isSelected && contract.contractExists !== undefined ?
            `<span class="${contract.contractExists ? 'balance' : 'activity'}" style="white-space: nowrap;">${contract.contractExists ? '✓ Active' : '✗ Expired'}</span>`
            : ''}
        </div>
      </div>
    `;
      }
    )
    .join("");

  // Add click handlers - directly load contract details
  document.querySelectorAll(".contract-card").forEach((card) => {
    card.addEventListener("click", async () => {
      const contractId = card.getAttribute("data-contract-id");
      if (contractId) {
        selectedContract = contractId;
        renderContracts(discoveredContracts);
        await connectToContract(contractId);
      }
    });
  });
}

async function renderContractDetails(details: ContractDetails) {
  const { contractId, contextRules } = details;

  // Hide contracts list section, show details section
  contractDetailsSection.style.display = "block";

  // Load policy params from RPC (batched - one call for all policies)
  const policyParams = await loadPolicyParamsFromRpc(contractId, contextRules);

  let html = `
    <div class="contract-full-id">${contractId}</div>
  `;

  // Render each context rule
  for (const rule of contextRules) {
    html += `
      <div class="context-rule">
        <h4>Context Rule #${rule.context_rule_id}</h4>
    `;

    // Group signers by type
    const externalSigners = rule.signers.filter((s: SignerInfo) => s.signer_type === 'External');
    const delegatedSigners = rule.signers.filter((s: SignerInfo) => s.signer_type === 'Delegated');
    const nativeSigners = rule.signers.filter((s: SignerInfo) => s.signer_type === 'Native');

    // Render External signers (passkeys) - group by verifier
    if (externalSigners.length > 0) {
      // Group by verifier address
      const byVerifier: Record<string, SignerInfo[]> = {};
      for (const signer of externalSigners) {
        const verifier = signer.signer_address || 'unknown';
        if (!byVerifier[verifier]) byVerifier[verifier] = [];
        byVerifier[verifier].push(signer);
      }

      for (const [verifier, signers] of Object.entries(byVerifier)) {
        html += `
          <div class="signer-group">
            <div class="signer-group-header">
              <span class="signer-type External">External</span>
              <span class="verifier-label">Verifier:</span>
              <span class="address-full">${verifier}</span>
            </div>
            <div class="signer-group-items">
        `;
        for (const signer of signers) {
          const isMyCredential = currentCredentialId && signer.credential_id?.toLowerCase() === currentCredentialId.toLowerCase();
          html += `
            <div class="credential-item ${isMyCredential ? 'highlight' : ''}">
              ${isMyCredential ? '<span class="you-badge">YOU</span>' : ''}
              <span class="address-full">${signer.credential_id}</span>
            </div>
          `;
        }
        html += `
            </div>
          </div>
        `;
      }
    }

    // Render Delegated signers
    if (delegatedSigners.length > 0) {
      html += `
        <div class="signer-group">
          <div class="signer-group-header">
            <span class="signer-type Delegated">Delegated</span>
          </div>
          <div class="signer-group-items">
      `;
      for (const signer of delegatedSigners) {
        const isMyAddress = currentSignerAddress && signer.signer_address === currentSignerAddress;
        html += `
          <div class="credential-item ${isMyAddress ? 'highlight' : ''}">
            ${isMyAddress ? '<span class="you-badge">YOU</span>' : ''}
            <span class="address-full">${signer.signer_address}</span>
          </div>
        `;
      }
      html += `
          </div>
        </div>
      `;
    }

    // Render Native signers
    if (nativeSigners.length > 0) {
      html += `
        <div class="signer-group">
          <div class="signer-group-header">
            <span class="signer-type Native">Native</span>
          </div>
          <div class="signer-group-items">
      `;
      for (const signer of nativeSigners) {
        const isMyAddress = currentSignerAddress && signer.signer_address === currentSignerAddress;
        html += `
          <div class="credential-item ${isMyAddress ? 'highlight' : ''}">
            ${isMyAddress ? '<span class="you-badge">YOU</span>' : ''}
            <span class="address-full">${signer.signer_address}</span>
          </div>
        `;
      }
      html += `
          </div>
        </div>
      `;
    }

    // Render Policies
    if (rule.policies && rule.policies.length > 0) {
      html += `
        <div class="signer-group">
          <div class="signer-group-header">
            <span class="signer-type Policy">Policies</span>
          </div>
          <div class="signer-group-items">
      `;
      for (const policy of rule.policies) {
        // Try RPC params first, fall back to indexer params
        const mapKey = `${rule.context_rule_id}:${policy.policy_address}`;
        const rpcParams = policyParams.get(mapKey);
        const params = rpcParams
          ? formatPolicyParamsFromRpc(rpcParams)
          : formatPolicyParams(policy.install_params);
        html += `
          <div class="credential-item">
            <span class="address-full">${policy.policy_address}</span>
            ${params ? `<span class="policy-params">${params}</span>` : ''}
          </div>
        `;
      }
      html += `
          </div>
        </div>
      `;
    }

    html += `</div>`;
  }

  contractDetailsEl.innerHTML = html;
}

function formatPolicyParams(params: any): string {
  if (!params || !params.map) return '';
  const parts: string[] = [];
  for (const item of params.map) {
    const key = item.key?.symbol;
    const val = item.val?.u32 ?? item.val?.i128;
    if (key && val !== undefined) {
      parts.push(`${key}: ${val}`);
    }
  }
  return parts.join(', ');
}

function hideContractDetails() {
  contractDetailsSection.style.display = "none";
}

// ============================================================================
// Event Handlers
// ============================================================================

authBtn.addEventListener("click", async () => {
  try {
    hideStatus();
    showStatus("Authenticating with passkey...", "info");

    // Start WebAuthn authentication
    // Note: In a real app, you'd get these options from your server
    // For this demo, we use a permissive configuration
    const authResponse = await startAuthentication({
      optionsJSON: {
        challenge: btoa(crypto.randomUUID()),
        rpId: window.location.hostname,
        allowCredentials: [], // Allow any credential
        userVerification: "preferred",
        timeout: 60000,
      },
    });

    showStatus("Authentication successful! Looking up contracts...", "info");

    // Reset selection for new lookup
    selectedContract = null;

    // The rawId from WebAuthn IS the credential ID we need
    // Convert from base64url to hex
    const rawIdBase64 = authResponse.rawId;
    const rawIdBytes = base64UrlToBytes(rawIdBase64);
    const credentialIdHex = bytesToHex(rawIdBytes);

    console.log("Credential ID (base64url):", rawIdBase64);
    console.log("Credential ID (hex):", credentialIdHex);

    // Store for highlighting in contract details
    currentCredentialId = credentialIdHex;
    currentSignerAddress = null;

    // Put it in the input for visibility
    publicKeyInput.value = credentialIdHex;

    // Automatically look up contracts
    discoveredContracts = await lookupContractsByCredentialId(credentialIdHex);

    if (discoveredContracts.length === 0) {
      showStatus(`No contracts found for credential ID: ${credentialIdHex.slice(0, 16)}...`, "info");
      renderContracts([]);
      return;
    }

    showStatus(`Found ${discoveredContracts.length} contract(s) for your passkey!`, "success");

    // Check if contracts still exist on-chain
    discoveredContracts = await Promise.all(
      discoveredContracts.map(enrichWithContractCheck)
    );

    // Always render contracts list first (this also auto-selects first contract)
    renderContracts(discoveredContracts);

    // Auto-connect to selected contract
    if (selectedContract) {
      await connectToContract(selectedContract);
    }
  } catch (error) {
    console.error("Authentication error:", error);
    showStatus(`Authentication failed: ${(error as Error).message}`, "error");
  }
});

// Helper: Convert base64url to bytes
function base64UrlToBytes(base64url: string): Uint8Array {
  // Add padding if needed
  const padding = "=".repeat((4 - (base64url.length % 4)) % 4);
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/") + padding;
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// Helper: Convert bytes to hex
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

lookupBtn.addEventListener("click", async () => {
  const credentialId = publicKeyInput.value.trim();

  if (!credentialId) {
    showStatus("Please enter a credential ID", "error");
    return;
  }

  try {
    hideStatus();
    showStatus("Looking up contracts...", "info");

    // Reset selection for new lookup
    selectedContract = null;

    // Store for highlighting in contract details
    currentCredentialId = credentialId.toLowerCase();
    currentSignerAddress = null;

    discoveredContracts = await lookupContractsByCredentialId(credentialId);

    if (discoveredContracts.length === 0) {
      showStatus("No contracts found for this public key", "info");
      renderContracts([]);
      return;
    }

    showStatus(`Found ${discoveredContracts.length} contract(s)`, "success");

    // Check if contracts still exist on-chain
    discoveredContracts = await Promise.all(
      discoveredContracts.map(enrichWithContractCheck)
    );

    // Always render contracts list first (this also auto-selects first contract)
    renderContracts(discoveredContracts);

    // Auto-connect to selected contract
    if (selectedContract) {
      await connectToContract(selectedContract);
    }
  } catch (error) {
    console.error("Lookup error:", error);
    showStatus(`Lookup failed: ${(error as Error).message}`, "error");
  }
});

// Helper function to connect to a contract and show details
async function connectToContract(contractId: string) {
  showStatus(`Loading contract details for ${truncateContractId(contractId)}...`, "info");

  try {
    const details = await getContractDetails(contractId);
    await renderContractDetails(details);
    showStatus(`Viewing details for ${truncateContractId(contractId)}`, "success");
  } catch (error) {
    console.error("Failed to get contract details:", error);
    showStatus(`Failed to load contract details: ${(error as Error).message}`, "error");
  }
}

addressLookupBtn.addEventListener("click", async () => {
  const address = stellarAddressInput.value.trim();

  if (!address) {
    showStatus("Please enter a Stellar address", "error");
    return;
  }

  try {
    hideStatus();
    showStatus("Looking up contracts by address...", "info");

    // Reset selection for new lookup
    selectedContract = null;

    // Track the address for highlighting, clear credential
    currentCredentialId = null;
    currentSignerAddress = address;

    discoveredContracts = await lookupContractsByAddress(address);

    if (discoveredContracts.length === 0) {
      showStatus("No contracts found for this address", "info");
      renderContracts([]);
      return;
    }

    showStatus(`Found ${discoveredContracts.length} contract(s)`, "success");

    // Check if contracts still exist on-chain
    discoveredContracts = await Promise.all(
      discoveredContracts.map(enrichWithContractCheck)
    );

    // Always render contracts list first (this also auto-selects first contract)
    renderContracts(discoveredContracts);

    // Auto-connect to selected contract
    if (selectedContract) {
      await connectToContract(selectedContract);
    }
  } catch (error) {
    console.error("Address lookup error:", error);
    showStatus(`Lookup failed: ${(error as Error).message}`, "error");
  }
});

backBtn.addEventListener("click", () => {
  hideContractDetails();
  showStatus("", "info");
  hideStatus();
});
