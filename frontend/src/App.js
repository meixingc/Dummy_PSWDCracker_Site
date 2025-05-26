import './App.css';

import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, Navigate } from 'react-router-dom';
import axios from 'axios';

function Login({ setUser }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post('http://localhost:4000/login', { username, password });
        setUser(res.data.username);
        localStorage.setItem('token', res.data.token);
    } catch (err) {
      setError(err.response?.data?.message || 'Login failed');
    }
  };

  return (
    <div>
      <h2>Login</h2>
      {error && <p style={{color:'red'}}>{error}</p>}
      <form onSubmit={handleLogin}>
        <input
          type="text"
          placeholder="Username"
          value={username}
          onChange={e => setUsername(e.target.value)}
          required
        />
        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={e => setPassword(e.target.value)}
          required
        />
        <button type="submit">Login</button>
      </form>
      <p>No account? <Link to="/signup">Sign Up</Link></p>
    </div>
  );
}

function Signup() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  const handleSignup = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post('http://localhost:4000/signup', { username, password });
      setMessage('User created! You can now login.');
      setError('');
      setUsername('');
      setPassword('');
    } catch (err) {
      setError(err.response?.data?.message || 'Signup failed');
      setMessage('');
    }
  };

  return (
    <div>
      <h2>Sign Up</h2>
      {message && <p style={{color:'green'}}>{message}</p>}
      {error && <p style={{color:'red'}}>{error}</p>}
      <form onSubmit={handleSignup}>
        <input
          type="text"
          placeholder="Username"
          value={username}
          onChange={e => setUsername(e.target.value)}
          required
        />
        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={e => setPassword(e.target.value)}
          required
        />
        <button type="submit">Sign Up</button>
      </form>
      <p>Have an account? <Link to="/">Login</Link></p>
    </div>
  );
}

function Welcome({ user, setUser }) {
  if (!user) {
    return <Navigate to="/" />;
  }

  const handleLogout = () => {
    setUser(null);
    localStorage.removeItem('token');
  };

  return (
    <div>
      <h2>You have logged in, welcome {user}</h2>
      <button onClick={handleLogout}>Logout</button>
      <p><Link to="/manager">Go to Password Manager</Link></p>
    </div>
  );
}

function PasswordManager({ user }) {
  const [account, setAccount] = useState('');
  const [accountUsername, setAccountUsername] = useState('');
  const [accountPassword, setAccountPassword] = useState('');
  const [passwords, setPasswords] = useState([]);
  const [error, setError] = useState('');
  const [token, setToken] = useState(localStorage.getItem('token'));

  // Load passwords
  const fetchPasswords = async () => {
    try {
      const res = await axios.get('http://localhost:4000/passwords', {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      setPasswords(res.data);
    } catch (err) {
      setError('Failed to load passwords');
    }
  };

  // Submit new password
  const handleSave = async (e) => {
    e.preventDefault();
    try {
      await axios.post(
        'http://localhost:4000/passwords',
        { account, username: accountUsername, password: accountPassword },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setAccount('');
      setAccountUsername('');
      setAccountPassword('');
      fetchPasswords(); // reload
    } catch (err) {
      setError('Failed to save password');
    }
  };

  // On first load
  React.useEffect(() => {
    fetchPasswords();
  }, []);

  if (!user) return <Navigate to="/" />;

  return (
    <div>
      <h2>Password Manager</h2>
      {error && <p style={{ color: 'red' }}>{error}</p>}

      <form onSubmit={handleSave}>
        <input
          type="text"
          placeholder="Account (e.g. Gmail)"
          value={account}
          onChange={(e) => setAccount(e.target.value)}
          required
        />
        <input
          type="text"
          placeholder="Username"
          value={accountUsername}
          onChange={(e) => setAccountUsername(e.target.value)}
          required
        />
        <input
          type="text"
          placeholder="Password"
          value={accountPassword}
          onChange={(e) => setAccountPassword(e.target.value)}
          required
        />
        <button type="submit">Save Password</button>
      </form>

      <h3>Saved Passwords</h3>
      <ul>
        {passwords.map((p) => (
          <li key={p.id}>
            <strong>{p.account}</strong> – {p.username}: {p.password}
          </li>
        ))}
      </ul>
    </div>
  );
}

function App() {
  const [user, setUser] = useState(null);

  return (
    <Router>
      <Routes>
        <Route path="/" element={user ? <Navigate to="/welcome" /> : <Login setUser={setUser} />} />
        <Route path="/signup" element={<Signup />} />
        <Route path="/welcome" element={<Welcome user={user} setUser={setUser} />} />
        <Route path="/manager" element={<PasswordManager user={user} />} />
      </Routes>
    </Router>
  );
}

export default App;
