import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './auth';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import DeepAnalysis from './pages/DeepAnalysis';

// Garde d'authentification : redirige vers /login si non connecté
function Protected({ children }) {
  const { user, loading } = useAuth();
  if (loading) {
    return <div className="loading"><div className="spinner"></div> Chargement...</div>;
  }
  if (!user) return <Navigate to="/login" replace />;
  return children;
}

function AppRoutes() {
  const { user } = useAuth();
  return (
    <Routes>
      <Route path="/login" element={user ? <Navigate to="/" replace /> : <Login />} />
      <Route path="/" element={<Protected><Dashboard /></Protected>} />
      <Route path="/incidents" element={<Protected><Dashboard /></Protected>} />
      <Route path="/incident/:caseId" element={<Protected><DeepAnalysis /></Protected>} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <AppRoutes />
      </BrowserRouter>
    </AuthProvider>
  );
}
