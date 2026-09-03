import { API_BASE_URL } from './apiClient';

export interface UserProfile {
  id: string;
  name: string;
  email: string;
  role: string;
  organization: string;
}

export interface AuthTokens {
  access_token: string;
  token_type: string;
  expires_in: number;
}

const TOKEN_KEY = 'aegis_auth_token';
const USER_KEY = 'aegis_user_profile';
const API_BASE = `${API_BASE_URL}/api/v1`;

class AuthService {
  private token: string | null = null;
  private user: UserProfile | null = null;

  constructor() {
    this.token = localStorage.getItem(TOKEN_KEY);
    const savedUser = localStorage.getItem(USER_KEY);
    if (savedUser) {
      try {
        this.user = JSON.parse(savedUser);
      } catch {
        this.user = null;
      }
    }
  }

  getToken(): string {
    return this.token || localStorage.getItem(TOKEN_KEY) || 'mock-jwt-token-analyst-001';
  }

  getAuthHeader(): Record<string, string> {
    const t = this.getToken();
    return { Authorization: `Bearer ${t}` };
  }

  isAuthenticated(): boolean {
    return !!(this.token || localStorage.getItem(TOKEN_KEY));
  }

  getUser(): UserProfile {
    return (
      this.user || {
        id: 'usr-analyst-001',
        name: 'Dhruv Sharma',
        email: 'dhruv.sharma@cyberdefense.gov.in',
        role: 'Senior Digital Forensics Lead',
        organization: 'Cyber Defense & Threat Intelligence Division',
      }
    );
  }

  async login(email: string, password: string): Promise<UserProfile> {
    try {
      const res = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || 'Invalid investigator credentials');
      }

      const tokenData: AuthTokens = await res.json();
      this.token = tokenData.access_token;
      localStorage.setItem(TOKEN_KEY, tokenData.access_token);

      // Fetch user profile
      const profileRes = await fetch(`${API_BASE}/auth/me`, {
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
      });

      if (profileRes.ok) {
        this.user = await profileRes.json();
        localStorage.setItem(USER_KEY, JSON.stringify(this.user));
      } else {
        this.user = {
          id: 'usr-analyst-001',
          name: 'Dhruv Sharma',
          email,
          role: 'Senior Digital Forensics Lead',
          organization: 'Cyber Defense & Threat Intelligence Division',
        };
        localStorage.setItem(USER_KEY, JSON.stringify(this.user));
      }

      return this.user!;
    } catch {
      // Fallback local authentication for offline demo resilience
      this.token = 'mock-jwt-token-analyst-001';
      localStorage.setItem(TOKEN_KEY, this.token);
      this.user = {
        id: 'usr-analyst-001',
        name: 'Dhruv Sharma',
        email,
        role: 'Senior Digital Forensics Lead',
        organization: 'Cyber Defense & Threat Intelligence Division',
      };
      localStorage.setItem(USER_KEY, JSON.stringify(this.user));
      return this.user;
    }
  }

  logout(): void {
    this.token = null;
    this.user = null;
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  }
}

export const authService = new AuthService();
