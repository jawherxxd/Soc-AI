import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../auth';

export default function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  async function handleSubmit() {
    setError('');
    setLoading(true);
    try {
      await login(username, password);
      navigate('/');
    } catch (e) {
      setError(e.message || 'Échec de la connexion');
    } finally {
      setLoading(false);
    }
  }

  function onKeyDown(e) {
    if (e.key === 'Enter') handleSubmit();
  }

  return (
    <div className="login-wrap">
      <div className="login-card">
        <div className="login-logo">
          <div className="logo-icon">🛡️</div>
          <div className="logo-text" style={{ fontSize: 20 }}>SOC<span>-AI</span></div>
        </div>
        <div className="login-title">Plateforme de supervision SOC</div>
        <div className="login-sub">Connectez-vous pour accéder au tableau de bord</div>

        {error && <div className="login-error">{error}</div>}

        <div className="field-group">
          <label>Nom d'utilisateur</label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            onKeyDown={onKeyDown}
            placeholder="admin"
            autoFocus
          />
        </div>
        <div className="field-group">
          <label>Mot de passe</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onKeyDown={onKeyDown}
            placeholder="••••••••"
          />
        </div>

        <button className="login-btn" onClick={handleSubmit} disabled={loading}>
          {loading ? 'Connexion...' : 'Se connecter'}
        </button>

        <div className="login-hint">SOC augmenté par IA</div>
      </div>
    </div>
  );
}
