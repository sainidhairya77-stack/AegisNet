import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { Layout } from './components/Layout';
import { Dashboard } from './pages/Dashboard';
import { PcapAnalyzer } from './pages/PcapAnalyzer';
import { Incidents } from './pages/Incidents';
import { NetworkGraph } from './pages/NetworkGraph';
import { ResponseSimulation } from './pages/ResponseSimulation';
import { Login } from './pages/Login';
import { Register } from './pages/Register';

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />

          <Route element={<Layout />}>
            <Route path="/" element={<Dashboard />} />
            <Route path="/analyzer" element={<PcapAnalyzer />} />
            <Route path="/incidents" element={<Incidents />} />
            <Route path="/topology" element={<NetworkGraph />} />
            <Route path="/simulation" element={<ResponseSimulation />} />
          </Route>

          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
};
