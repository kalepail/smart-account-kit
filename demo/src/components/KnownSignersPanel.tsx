import { useState, useEffect, useCallback } from "react";
import type { SmartAccountKit, StoredCredential } from "smart-account-kit";

interface KnownSignersPanelProps {
  kit: SmartAccountKit;
  isConnected: boolean;
  contractId: string | null;
  onLog: (message: string, type?: "info" | "success" | "error") => void;
}

/**
 * Format a date for display
 */
function formatDate(timestamp: number): string {
  return new Date(timestamp).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/**
 * Truncate a string for display
 */
function truncate(str: string, length: number = 20): string {
  if (str.length <= length) return str;
  return `${str.slice(0, length)}...`;
}

export function KnownSignersPanel({
  kit,
  isConnected,
  contractId,
  onLog,
}: KnownSignersPanelProps) {
  const [credentials, setCredentials] = useState<StoredCredential[]>([]);
  const [loading, setLoading] = useState(false);

  const fetchCredentials = useCallback(async () => {
    setLoading(true);
    try {
      const allCreds = await kit.credentials.getAll();
      setCredentials(allCreds);
    } catch (error) {
      onLog(`Failed to fetch credentials: ${error}`, "error");
    } finally {
      setLoading(false);
    }
  }, [kit, onLog]);

  useEffect(() => {
    fetchCredentials();
  }, [fetchCredentials]);

  // Filter to show only deployed credentials (those associated with the current wallet)
  const walletCredentials = credentials.filter(
    (c) => contractId && c.contractId === contractId && !c.deploymentStatus
  );

  // Pending credentials (not yet deployed)
  const pendingCredentials = credentials.filter(
    (c) => c.deploymentStatus === "pending" || c.deploymentStatus === "failed"
  );

  if (!isConnected) {
    // Show pending credentials even when not connected
    if (pendingCredentials.length === 0) {
      return null;
    }

    return (
      <div className="card pending-credentials-card">
        <h3>Pending Credentials</h3>
        <p className="panel-description">
          These passkeys were created but wallet deployment is incomplete. You can deploy them to
          create a wallet.
        </p>
        <div className="credentials-list">
          {pendingCredentials.map((cred) => (
            <PendingCredentialItem
              key={cred.credentialId}
              credential={cred}
              kit={kit}
              onLog={onLog}
              onRefresh={fetchCredentials}
            />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="card">
      <div className="section-header">
        <h3>Known Signers (Local Storage)</h3>
        <button className="small secondary" onClick={fetchCredentials} disabled={loading}>
          {loading ? <span className="spinner" /> : "Refresh"}
        </button>
      </div>

      <p className="panel-description">
        Locally stored credentials that the app knows about. These are passkeys stored in your
        browser that can be used to sign transactions.
      </p>

      {loading && credentials.length === 0 ? (
        <div className="loading-state">
          <span className="spinner" /> Loading...
        </div>
      ) : walletCredentials.length === 0 ? (
        <div className="empty-state">
          No stored credentials. Passkey information is stored in your device's credential manager.
        </div>
      ) : (
        <div className="credentials-list">
          {walletCredentials.map((cred) => (
            <CredentialItem key={cred.credentialId} credential={cred} />
          ))}
        </div>
      )}
    </div>
  );
}

/**
 * Individual credential item display
 */
function CredentialItem({ credential }: { credential: StoredCredential }) {
  return (
    <div className="credential-item">
      <div className="credential-info">
        <div className="nickname">
          {credential.nickname || "Unnamed Passkey"}
          {credential.isPrimary && <span className="primary-badge">Primary</span>}
          <span className="status-badge deployed">Active</span>
        </div>
        <div className="credential-details">
          <div className="detail-row">
            <span className="detail-label">Credential ID</span>
            <span className="detail-value">{truncate(credential.credentialId, 40)}</span>
          </div>
          <div className="detail-row">
            <span className="detail-label">Created</span>
            <span className="detail-value">{formatDate(credential.createdAt)}</span>
          </div>
          {credential.lastUsedAt && (
            <div className="detail-row">
              <span className="detail-label">Last Used</span>
              <span className="detail-value">{formatDate(credential.lastUsedAt)}</span>
            </div>
          )}
          {credential.deviceType && (
            <div className="detail-row">
              <span className="detail-label">Device Type</span>
              <span className="detail-value">
                {credential.deviceType === "multiDevice" ? "Synced Passkey" : "Device-bound"}
                {credential.backedUp && " (Backed up)"}
              </span>
            </div>
          )}
          {credential.contextRuleId !== undefined && (
            <div className="detail-row">
              <span className="detail-label">Context Rule</span>
              <span className="detail-value">#{credential.contextRuleId}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/**
 * Pending credential item with actions
 */
function PendingCredentialItem({
  credential,
  kit,
  onLog,
  onRefresh,
}: {
  credential: StoredCredential;
  kit: SmartAccountKit;
  onLog: (message: string, type?: "info" | "success" | "error") => void;
  onRefresh: () => void;
}) {
  const [deploying, setDeploying] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const handleDeploy = async () => {
    setDeploying(true);
    onLog(`Deploying credential ${truncate(credential.credentialId)}...`);

    try {
      const result = await kit.credentials.deploy(credential.credentialId, {
        autoSubmit: true,
      });

      if (result.submitResult?.success) {
        onLog("Wallet deployed successfully!", "success");
        onRefresh();
        // Page will need to reconnect to the new wallet
        window.location.reload();
      } else {
        throw new Error(result.submitResult?.error || "Deployment failed");
      }
    } catch (error) {
      onLog(`Deployment failed: ${error}`, "error");
      onRefresh();
    } finally {
      setDeploying(false);
    }
  };

  const handleDelete = async () => {
    if (!confirm("Delete this pending credential? The passkey will remain on your device.")) {
      return;
    }

    setDeleting(true);
    try {
      await kit.credentials.delete(credential.credentialId);
      onLog("Credential removed from storage", "success");
      onRefresh();
    } catch (error) {
      onLog(`Failed to delete: ${error}`, "error");
    } finally {
      setDeleting(false);
    }
  };

  return (
    <div className="credential-item pending">
      <div className="credential-info">
        <div className="nickname">
          {credential.nickname || "Unnamed"}
          <span className={`status-badge ${credential.deploymentStatus}`}>
            {credential.deploymentStatus === "pending" ? "Pending" : "Failed"}
          </span>
        </div>
        <div className="id">{truncate(credential.credentialId, 40)}</div>
        {credential.deploymentError && (
          <div className="error-text">{credential.deploymentError}</div>
        )}
        <div className="credential-date">Created: {formatDate(credential.createdAt)}</div>
      </div>
      <div className="credential-actions">
        <button className="small" onClick={handleDeploy} disabled={deploying || deleting}>
          {deploying ? <span className="spinner" /> : "Deploy"}
        </button>
        <button className="small danger" onClick={handleDelete} disabled={deploying || deleting}>
          {deleting ? <span className="spinner" /> : "Delete"}
        </button>
      </div>
    </div>
  );
}
