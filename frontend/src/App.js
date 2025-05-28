import './App.css';
import React, { useState } from 'react';
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Link,
  Navigate
} from 'react-router-dom';
import axios from 'axios';

// login form component
function Login({ setUser }) {
  const [username, setUsername] = useState('');
  const [pwd, setPwd] = useState('');
  const [err, setErr] = useState('');

  // this logs you in, if all goes well
  const tryLogin = async (e) => {
    e.preventDefault();

    try {
      const loginRes = await axios.post('http://localhost:4000/login', {
        username: username,
        password: pwd,
      });

      setUser(loginRes.data.username); // yay success
      localStorage.setItem('token', loginRes.data.token); // store it for later
    } catch (err) {
      // show msg from server or fallback
      setErr(err?.response?.data?.message || 'login didn\'t work');
    }
  };

  return (
    <div>
      <h2>Login</h2>
      {err && <p style={{ color: 'red' }}>{err}</p>}
      <form onSubmit={tryLogin}>
        <input
          type="text"
          placeholder="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          required
        />
        <input
          type="password"
          placeholder="Password"
          value={pwd}
          onChange={(e) => setPwd(e.target.value)}
          required
        />
        <button type="submit">Login</button>
      </form>
      <p>
        no account? <Link to="/signup">Sign Up</Link>
      </p>
    </div>
  );
}

// sign up screen
function Signup() {
  const [newUser, setNewUser] = useState('');
  const [newPwd, setNewPwd] = useState('');
  const [msg, setMsg] = useState('');
  const [failMsg, setFailMsg] = useState('');

  // creates an account
  const handleSignup = async (e) => {
    e.preventDefault();

    try {
      await axios.post('http://localhost:4000/signup', {
        username: newUser,
        password: newPwd,
      });

      setMsg('user created! you can now login.');
      setFailMsg('');
      setNewUser('');
      setNewPwd('');
    } catch (err) {
      setFailMsg(err?.response?.data?.message || 'signup had an issue');
      setMsg('');
    }
  };

  return (
    <div>
      <h2>Sign Up</h2>
      {msg && <p style={{ color: 'green' }}>{msg}</p>}
      {failMsg && <p style={{ color: 'red' }}>{failMsg}</p>}
      <form onSubmit={handleSignup}>
        <input
          type="text"
          placeholder="Username"
          value={newUser}
          onChange={(e) => setNewUser(e.target.value)}
          required
        />
        <input
          type="password"
          placeholder="Password"
          value={newPwd}
          onChange={(e) => setNewPwd(e.target.value)}
          required
        />
        <button type="submit">Sign Up</button>
      </form>
      <p>
        have an account? <Link to="/">Login</Link>
      </p>
    </div>
  );
}

// welcome page after login
function Welcome({ user, setUser }) {
  // if someone sneaks here without login, send em back
  if (!user) return <Navigate to="/" />;

  const logoutUser = () => {
    setUser(null);
    localStorage.removeItem('token'); // forget the token
  };

  return (
    <div>
      <h2>you have logged in, welcome {user}</h2>
      <button onClick={logoutUser}>Logout</button>
      <p>
        <Link to="/manager">Go to Password Manager</Link>
      </p>
    </div>
  );
}

// vault - where the password magic happens
function Vault({ token }) {
  const [site, setSite] = useState('');
  const [login, setLogin] = useState('');
  const [pw, setPw] = useState('');
  const [master, setMaster] = useState('');
  const [viewKey, setViewKey] = useState('');
  const [saved, setSaved] = useState([]);
  const [canSee, setCanSee] = useState(false);

  // adds a password to the vault
  const savePassword = async () => {
    if (!master) {
      alert('please type master password first!');
      return;
    }

    try {
      await axios.post(
        'http://localhost:4000/vault/add',
        {
          site: site,
          login: login,
          password: pw,
          masterPassword: master,
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      alert('password saved!');
      setSite('');
      setLogin('');
      setPw('');
    } catch (err) {
      console.log('save error:', err);
      alert('failed to save password');
    }
  };

  // unlocks saved passwords
  const fetchPasswords = async () => {
    if (!viewKey) {
      alert('need the view password key');
      return;
    }

    try {
      const res = await axios.post(
        'http://localhost:4000/vault/list',
        {
          masterPassword: viewKey,
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      setSaved(res.data);
      setCanSee(true);
    } catch (err) {
      console.error('unlock failed', err);
      alert('wrong view key or something broke');
      setCanSee(false);
      setSaved([]);
    }
  };

  return (
    <div>
      <h2>Password Vault</h2>

      <h3>Add New Entry</h3>
      <input
        placeholder="Master Password (to encrypt)"
        type="password"
        value={master}
        onChange={(e) => setMaster(e.target.value)}
      />
      <input
        placeholder="Site"
        value={site}
        onChange={(e) => setSite(e.target.value)}
      />
      <input
        placeholder="Login"
        value={login}
        onChange={(e) => setLogin(e.target.value)}
      />
      <input
        type="password"
        placeholder="Password"
        value={pw}
        onChange={(e) => setPw(e.target.value)}
      />
      <button onClick={savePassword}>Add</button>

      <h3>Unlock Saved Passwords</h3>
      <input
        placeholder="Enter Master Password"
        type="password"
        value={viewKey}
        onChange={(e) => setViewKey(e.target.value)}
      />
      <button onClick={fetchPasswords}>Unlock Passwords</button>

      {canSee ? (
        <>
          <h3>Saved Passwords</h3>
          <ul>
            {saved.map((entry, idx) => (
              <li key={idx}>
                {entry.site} - {entry.login}: {entry.password}
              </li>
            ))}
          </ul>
        </>
      ) : (
        <p style={{ color: 'gray' }}>
          Enter a master password to see saved passwords.
        </p>
      )}
    </div>
  );
}

// main app layout
function App() {
  const [user, setUser] = useState(null);
  const token = localStorage.getItem('token'); // yay persistence

  return (
    <Router>
      <Routes>
        <Route
          path="/"
          element={
            user ? <Navigate to="/welcome" /> : <Login setUser={setUser} />
          }
        />
        <Route path="/signup" element={<Signup />} />
        <Route
          path="/welcome"
          element={<Welcome user={user} setUser={setUser} />}
        />
        <Route path="/manager" element={<Vault token={token} />} />
      </Routes>
    </Router>
  );
}

export default App;
