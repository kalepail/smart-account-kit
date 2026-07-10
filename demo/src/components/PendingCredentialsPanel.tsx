import type { StoredCredential } from "smart-account-kit";

interface PendingCredentialsPanelProps {
  pendingCredentials: StoredCredential[];
  loading: string | null;
  onDeploy: (credential: StoredCredential) => void;
  onDelete: (credential: StoredCredential) => void;
}

/** Card listing passkeys whose wallet deployment failed / is incomplete. */
export function PendingCredentialsPanel({
  pendingCredentials,
  loading,
  onDeploy,
  onDelete,
}: PendingCredentialsPanelProps) {
  return (
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
                onClick={() => onDeploy(cred)}
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
                onClick={() => onDelete(cred)}
                disabled={loading !== null}
              >
                Delete
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
