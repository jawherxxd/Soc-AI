import { NavLink } from 'react-router-dom';
import { useAuth } from '../auth';

export default function Sidebar() {
  const { user, logout } = useAuth();
  const initial = (user?.full_name || user?.username || '?').charAt(0).toUpperCase();

  return (
    <aside className="sidebar">
      <div className="logo">
        <div className="logo-icon">🛡️</div>
        <div className="logo-text">SOC<span>-AI</span></div>
      </div>

      <NavLink to="/" end className={({ isActive }) => 'nav-item' + (isActive ? ' active' : '')}>
        <span className="nav-icon">▤</span> Dashboard
      </NavLink>
      <NavLink to="/incidents" className={({ isActive }) => 'nav-item' + (isActive ? ' active' : '')}>
        <span className="nav-icon">⚠</span> Incidents
      </NavLink>
      {user?.role === 'admin' && (
        <NavLink to="/admin" className={({ isActive }) => 'nav-item' + (isActive ? ' active' : '')}>
          <span className="nav-icon">⚙</span> Administration
        </NavLink>
      )}

      <div className="sidebar-footer">
        <div className="avatar">{initial}</div>
        <div className="user-info">
          <div className="name">{user?.full_name || user?.username}</div>
          <div className="role">{user?.role === 'admin' ? 'Administrateur' : 'Analyste SOC'}</div>
        </div>
        <button className="logout-btn" onClick={logout} title="Déconnexion">⏻</button>
      </div>
    </aside>
  );
}
