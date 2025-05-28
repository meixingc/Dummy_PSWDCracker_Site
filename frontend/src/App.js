import './App.css';
import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, Navigate } from 'react-router-dom';
import axios from 'axios';

// Login Component
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
      {error && <p style={{ color: 'red' }}>{error}</p>}
      <form onSubmit={handleLogin}>
        <input type="text" placeholder="Username" value={username} onChange={e => setUsername(e.target.value)} required />
        <input type="password" placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} required />
        <button type="submit">Login</button>
      </form>
      <p>No account? <Link to="/signup">Sign Up</Link></p>
    </div>
  );
}

// Signup Component
function Signup() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  const handleSignup = async (e) => {
    e.preventDefault();
    try {
      await axios.post('http://localhost:4000/signup', { username, password });
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
      {message && <p style={{ color: 'green' }}>{message}</p>}
      {error && <p style={{ color: 'red' }}>{error}</p>}
      <form onSubmit={handleSignup}>
        <input type="text" placeholder="Username" value={username} onChange={e => setUsername(e.target.value)} required />
        <input type="password" placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} required />
        <button type="submit">Sign Up</button>
      </form>
      <p>Have an account? <Link to="/">Login</Link></p>
    </div>
  );
}

// Welcome Component
function Welcome({ user, setUser }) {
  if (!user) return <Navigate to="/" />;

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

// Vault Component
function Vault({ token }) {
  const [site, setSite] = useState('');
  const [login, setLogin] = useState('');
  const [password, setPassword] = useState('');
  const [masterPassword, setMasterPassword] = useState('');
  const [viewKey, setViewKey] = useState('');
  const [entries, setEntries] = useState([]);
  const [unlocked, setUnlocked] = useState(false);

  const addEntry = async () => {
    if (!masterPassword) {
      alert('Please enter master password to add an entry');
      return;
    }
    try {
      await axios.post('http://localhost:4000/vault/add',
        { site, login, password, masterPassword },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      alert('Password saved!');
      setSite('');
      setLogin('');
      setPassword('');
    } catch (err) {
      console.error(err);
      alert('Failed to save password');
    }
  };

  const unlockPasswords = async () => {
    if (!viewKey) {
      alert('Please enter the view password key');
      return;
    }
    try {
      const res = await axios.post('http://localhost:4000/vault/list',
        { masterPassword: viewKey },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setEntries(res.data);
      setUnlocked(true);
    } catch (err) {
      console.error(err);
      alert('Incorrect password to unlock saved passwords');
      setUnlocked(false);
      setEntries([]);
    }
  };

  return (
    <div>
      <h2>Password Vault</h2>

      <h3>Add New Entry</h3>
      <input placeholder="Master Password (to encrypt)" type="password" value={masterPassword} onChange={e => setMasterPassword(e.target.value)} />
      <input placeholder="Site" value={site} onChange={e => setSite(e.target.value)} />
      <input placeholder="Login" value={login} onChange={e => setLogin(e.target.value)} />
      <input placeholder="Password" type="password" value={password} onChange={e => setPassword(e.target.value)} />
      <button onClick={addEntry}>Add</button>

      <h3>Unlock Saved Passwords</h3>
      <input placeholder="View Password Key (to decrypt)" type="password" value={viewKey} onChange={e => setViewKey(e.target.value)} />
      <button onClick={unlockPasswords}>Unlock Passwords</button>

      {unlocked ? (
        <>
          <h3>Saved Passwords</h3>
          <ul>
            {entries.map((entry, i) => (
              <li key={i}>{entry.site} - {entry.login}: {entry.password}</li>
            ))}
          </ul>
        </>
      ) : (
        <p style={{ color: 'gray' }}>Enter the view key to see saved passwords.</p>
      )}
    </div>
  );
}

// Main App Component
function App() {
  const [user, setUser] = useState(null);
  const token = localStorage.getItem('token');

  return (
    <Router>
      <Routes>
        <Route path="/" element={user ? <Navigate to="/welcome" /> : <Login setUser={setUser} />} />
        <Route path="/signup" element={<Signup />} />
        <Route path="/welcome" element={<Welcome user={user} setUser={setUser} />} />
        <Route path="/manager" element={<Vault token={token} />} />
      </Routes>
    </Router>
  );
}

export default App;
