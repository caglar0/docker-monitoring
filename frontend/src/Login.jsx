import React, { useState } from "react";
import { ShieldAlert, Lock } from "lucide-react";

const API = "http://localhost:8000";

export default function Login({ onLoginSuccess }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const res = await fetch(`${API}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.detail || "Giriş başarısız");
      }
      const data = await res.json();
      localStorage.setItem("auth_token", data.token);
      localStorage.setItem("auth_user", data.username);
      onLoginSuccess(data.token, data.username);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4">
      <div className="w-full max-w-sm">
        <div className="flex flex-col items-center gap-2 mb-6">
          <ShieldAlert className="text-cyan-400 w-10 h-10" />
          <h1 className="text-lg font-mono font-bold text-slate-200 tracking-wider">
            CONTAINER MONITORING
          </h1>
        </div>
        <form
          onSubmit={handleSubmit}
          className="bg-slate-900 border border-slate-800 rounded-lg p-6 space-y-4"
        >
          <div>
            <label className="text-xs font-mono text-slate-400 block mb-1.5">
              Kullanıcı Adı
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 px-3 py-2 rounded text-slate-200 text-sm font-mono focus:outline-none focus:border-cyan-500"
              autoFocus
            />
          </div>
          <div>
            <label className="text-xs font-mono text-slate-400 block mb-1.5">
              Şifre
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 px-3 py-2 rounded text-slate-200 text-sm font-mono focus:outline-none focus:border-cyan-500"
            />
          </div>
          {error && (
            <p className="text-rose-400 text-xs font-mono">{error}</p>
          )}
          <button
            type="submit"
            disabled={loading}
            className="w-full bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-mono font-bold text-sm py-2.5 rounded transition-colors flex items-center justify-center gap-2"
          >
            <Lock className="w-4 h-4" />
            {loading ? "Giriş yapılıyor..." : "Giriş Yap"}
          </button>
        </form>
      </div>
    </div>
  );
}
