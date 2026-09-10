import React, { createContext, useContext, useState, useEffect } from 'react';
import { User, UserRole } from '../types';
import { api } from '../services/api';

interface AuthContextType {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  systemStatus: 'connected' | 'demo';
  login: (username: string, password: string) => Promise<void>;
  register: (username: string, email: string, password: string, fullName?: string) => Promise<void>;
  loginDemo: (role?: UserRole) => void;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(localStorage.getItem('aegisnet_token'));
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [systemStatus, setSystemStatus] = useState<'connected' | 'demo'>('demo');

  useEffect(() => {
    const initAuth = async () => {
      try {
        const health = await api.checkHealth();
        setSystemStatus(health.status === 'ok' ? 'connected' : 'demo');

        const savedToken = localStorage.getItem('aegisnet_token');
        if (savedToken) {
          const currentUser = await api.getMe();
          setUser(currentUser);
        } else {
          // Auto-seed with demo user for seamless access
          loginDemo('ANALYST');
        }
      } catch {
        loginDemo('ANALYST');
      } finally {
        setIsLoading(false);
      }
    };

    initAuth();
  }, []);

  const login = async (username: string, password: string) => {
    setIsLoading(true);
    try {
      const authRes = await api.login({ username, password });
      setToken(authRes.access_token);
      const currentUser = await api.getMe();
      setUser(currentUser);
    } finally {
      setIsLoading(false);
    }
  };

  const register = async (username: string, email: string, password: string, fullName?: string) => {
    setIsLoading(true);
    try {
      await api.register({ username, email, password, full_name: fullName });
      await login(username, password);
    } finally {
      setIsLoading(false);
    }
  };

  const loginDemo = (role: UserRole = 'ANALYST') => {
    const demoToken = `demo-${role.toLowerCase()}-token-${Date.now()}`;
    localStorage.setItem('aegisnet_token', demoToken);
    setToken(demoToken);
    setUser({
      id: `demo-user-${role.toLowerCase()}`,
      username: role === 'ADMIN' ? 'secops_admin' : 'phase3analyst',
      email: `${role.toLowerCase()}@aegisnet.security`,
      full_name: role === 'ADMIN' ? 'AegisNet Administrator' : 'Lead Defense Analyst',
      role,
      is_active: true,
      created_at: new Date().toISOString(),
    });
  };

  const logout = () => {
    localStorage.removeItem('aegisnet_token');
    setToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: !!user,
        isLoading,
        systemStatus,
        login,
        register,
        loginDemo,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
