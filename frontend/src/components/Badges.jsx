// Petits composants réutilisables

export function SeverityBadge({ severity }) {
  const sev = (severity || 'low').toLowerCase();
  const labels = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
  return (
    <span className={`sev sev-${sev}`}>
      <span className="sev-dot"></span>
      {labels[sev] || severity}
    </span>
  );
}

export function StatusBadge({ status }) {
  const labels = {
    pending_approval: "En attente",
    open: 'Ouvert',
    closed_tp: 'Clôturé (TP)',
    closed_fp: 'Clôturé (FP)',
    resolved: 'Résolu',
  };
  return <span className={`status ${status || ''}`}>{labels[status] || status}</span>;
}
