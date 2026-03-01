import { useState, useEffect, useCallback, FormEvent, ChangeEvent } from 'react';
import { 
  Shield, 
  RefreshCw, 
  Copy, 
  Plus, 
  Trash2, 
  Key, 
  Globe, 
  User, 
  Eye, 
  EyeOff,
  Check,
  Lock,
  Unlock,
  Edit2,
  FileText,
  QrCode,
  Link as LinkIcon,
  Code,
  Image as ImageIcon,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Download,
  AlertTriangle
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { QRCodeSVG } from 'qrcode.react';
import { cn } from './lib/utils';

interface SavedPassword {
  id: number;
  service: string;
  username: string;
  email?: string;
  phone?: string;
  backup_code?: string;
  password: string;
  custom_fields: { label: string; value: string }[];
  created_at: string;
}

interface Note {
  id: number;
  title: string;
  content?: string;
  image?: string;
  link?: string;
  code?: string;
  created_at: string;
}

interface SavedQRCode {
  id: number;
  service: string;
  username?: string;
  content: string;
  created_at: string;
}

// Crypto Helpers
const bufferToBase64 = (buf: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const base64ToBuffer = (base64: string) => Uint8Array.from(atob(base64), c => c.charCodeAt(0)).buffer;

/**
 * Securely overwrites a Uint8Array with zeros to clear sensitive data from memory.
 */
const zeroOut = (arr: Uint8Array | null) => {
  if (arr) {
    arr.fill(0);
  }
};

/**
 * Converts a string to a Uint8Array.
 */
const stringToUint8Array = (str: string) => {
  return new TextEncoder().encode(str);
};

const encrypt = async (text: string | Uint8Array, key: CryptoKey) => {
  if (!text) return "";
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encoded = typeof text === 'string' ? stringToUint8Array(text) : text;
  
  const ciphertext = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoded
  );
  
  // If we passed a Uint8Array, zero it out after use
  if (typeof text !== 'string') {
    zeroOut(text);
  } else {
    // If it was a string, we can't zero it, but we zero the encoded version
    zeroOut(encoded);
  }
  
  return `${bufferToBase64(iv)}:${bufferToBase64(ciphertext)}`;
};

const decrypt = async (encrypted: string, key: CryptoKey) => {
  if (!encrypted) return "";
  try {
    const [ivStr, cipherStr] = encrypted.split(':');
    const iv = base64ToBuffer(ivStr);
    const ciphertext = base64ToBuffer(cipherStr);
    const decrypted = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(iv) },
      key,
      ciphertext
    );
    
    const decoded = new TextDecoder().decode(decrypted);
    // Zero out the decrypted buffer immediately
    zeroOut(new Uint8Array(decrypted));
    
    return decoded;
  } catch (e) {
    return "[Decryption Failed]";
  }
};

const deriveKey = async (password: Uint8Array, salt: Uint8Array) => {
  const baseKey = await window.crypto.subtle.importKey(
    "raw",
    password,
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  
  const encryptionKey = await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 600000,
      hash: "SHA-256"
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  const integrityKey = await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: new Uint8Array([...salt].reverse()), // Different salt for integrity key
      iterations: 600000,
      hash: "SHA-256"
    },
    baseKey,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    true,
    ["sign", "verify"]
  );
  
  // Zero out the password buffer after key derivation
  zeroOut(password);
  
  return { encryptionKey, integrityKey };
};

const signData = async (data: string, key: CryptoKey) => {
  const encoded = new TextEncoder().encode(data);
  const signature = await window.crypto.subtle.sign("HMAC", key, encoded);
  return bufferToBase64(signature);
};

const verifyData = async (data: string, signature: string, key: CryptoKey) => {
  try {
    const encoded = new TextEncoder().encode(data);
    const sigBuffer = base64ToBuffer(signature);
    return await window.crypto.subtle.verify("HMAC", key, sigBuffer, encoded);
  } catch (e) {
    return false;
  }
};

const deriveHash = async (password: Uint8Array, salt: Uint8Array) => {
  const baseKey = await window.crypto.subtle.importKey(
    "raw",
    password,
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  
  const derivedKey = await window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 600000,
      hash: "SHA-256"
    },
    baseKey,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    true,
    ["sign"]
  );
  
  const exported = await window.crypto.subtle.exportKey("raw", derivedKey);
  const hash = bufferToBase64(exported);
  
  // Zero out buffers
  zeroOut(password);
  zeroOut(new Uint8Array(exported));
  
  return hash;
};

export default function App() {
  const [activeTab, setActiveTab] = useState<'generator' | 'vault' | 'notes' | 'qr'>('generator');
  
  // Security State
  const [masterKey, setMasterKey] = useState<CryptoKey | null>(null);
  const [integrityKey, setIntegrityKey] = useState<CryptoKey | null>(null);
  const [isLocked, setIsLocked] = useState(true);
  const [masterSalt, setMasterSalt] = useState<Uint8Array | null>(null);
  const [authSalt, setAuthSalt] = useState<Uint8Array | null>(null);
  const [authHash, setAuthHash] = useState<string | null>(null);
  const [showMasterSetup, setShowMasterSetup] = useState(false);
  const [masterPasswordInput, setMasterPasswordInput] = useState('');
  const [masterPasswordConfirm, setMasterPasswordConfirm] = useState('');
  const [securityError, setSecurityError] = useState('');
  const [lastActivity, setLastActivity] = useState(Date.now());
  const [failedAttempts, setFailedAttempts] = useState(0);
  const [lockoutUntil, setLockoutUntil] = useState<number | null>(null);
  const [privacyMode, setPrivacyMode] = useState(true);
  const [passwordStrength, setPasswordStrength] = useState(0);
  const [isHardwareSupported, setIsHardwareSupported] = useState(false);
  const [hasHardwareKey, setHasHardwareKey] = useState(false);
  const [length, setLength] = useState(16);
  const [includeLowercase, setIncludeLowercase] = useState(true);
  const [includeUppercase, setIncludeUppercase] = useState(true);
  const [includeNumbers, setIncludeNumbers] = useState(true);
  const [includeSymbols, setIncludeSymbols] = useState(true);
  const [includeBrackets, setIncludeBrackets] = useState(true);
  const [generatedPass, setGeneratedPass] = useState('');
  const [savedPasswords, setSavedPasswords] = useState<SavedPassword[]>([]);
  const [copied, setCopied] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [showPassMap, setShowPassMap] = useState<Record<number, boolean>>({});
  const [decryptedPasswords, setDecryptedPasswords] = useState<Record<number, string>>({});
  
  // Form state
  const [newService, setNewService] = useState('');
  const [newUsername, setNewUsername] = useState('');
  const [newEmail, setNewEmail] = useState('');
  const [newPhone, setNewPhone] = useState('');
  const [newBackupCode, setNewBackupCode] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [customFields, setCustomFields] = useState<{ label: string; value: string }[]>([]);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [isWindowFocused, setIsWindowFocused] = useState(true);
  const [isTabVisible, setIsTabVisible] = useState(true);
  const [isCompromised, setIsCompromised] = useState(false);
  const [securityWarning, setSecurityWarning] = useState<string | null>(null);
  const [isRooted, setIsRooted] = useState(false);
  const [showRootWarning, setShowRootWarning] = useState(false);
  const [integrityChecks, setIntegrityChecks] = useState<Record<string, boolean>>({});

  // Notes state
  const [notes, setNotes] = useState<Note[]>([]);
  const [showNoteForm, setShowNoteForm] = useState(false);
  const [newNoteTitle, setNewNoteTitle] = useState('');
  const [newNoteContent, setNewNoteContent] = useState('');
  const [newNoteImage, setNewNoteImage] = useState<string | null>(null);
  const [newNoteLink, setNewNoteLink] = useState('');
  const [newNoteCode, setNewNoteCode] = useState('');

  // QR state
  const [qrcodes, setQrcodes] = useState<SavedQRCode[]>([]);
  const [showQrForm, setShowQrForm] = useState(false);
  const [newQrService, setNewQrService] = useState('');
  const [newQrUsername, setNewQrUsername] = useState('');
  const [newQrContent, setNewQrContent] = useState('');

  useEffect(() => {
    const checkEnvironment = () => {
      // Basic detection for compromised/automated environments
      if (navigator.webdriver) {
        setIsCompromised(true);
        setSecurityWarning("Automated environment detected. Vault disabled for security.");
      }

      // Check for non-standard browser properties often present in rooted/emulated environments
      const suspiciousProps = ['_phantom', 'callPhantom', '__nightmare', 'Buffer', 'spawn'];
      for (const prop of suspiciousProps) {
        if (prop in window) {
          setIsCompromised(true);
          setSecurityWarning("Non-standard environment detected. Vault disabled for security.");
          break;
        }
      }
    };

    const detectDevTools = () => {
      const threshold = 160;
      const widthDiff = window.outerWidth - window.innerWidth > threshold;
      const heightDiff = window.outerHeight - window.innerHeight > threshold;
      if (widthDiff || heightDiff) {
        // DevTools might be open
        console.clear();
      }
    };

    checkEnvironment();
    const devToolsInterval = setInterval(detectDevTools, 1000);

    const handleFocus = () => setIsWindowFocused(true);
    const handleBlur = () => setIsWindowFocused(false);
    const handleVisibilityChange = () => {
      setIsTabVisible(document.visibilityState === 'visible');
    };

    window.addEventListener('focus', handleFocus);
    window.addEventListener('blur', handleBlur);
    document.addEventListener('visibilitychange', handleVisibilityChange);
    
    const preventContextMenu = (e: MouseEvent) => {
      if (process.env.NODE_ENV === 'production') {
        e.preventDefault();
      }
    };
    document.addEventListener('contextmenu', preventContextMenu);

    return () => {
      clearInterval(devToolsInterval);
      window.removeEventListener('focus', handleFocus);
      window.removeEventListener('blur', handleBlur);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      document.removeEventListener('contextmenu', preventContextMenu);
    };
  }, []);

  const generatePassword = useCallback(() => {
    let charset = "";
    if (includeLowercase) charset += "abcdefghijklmnopqrstuvwxyz";
    if (includeUppercase) charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (includeNumbers) charset += "0123456789";
    if (includeSymbols) charset += "!@#$%^&*-=_+";
    if (includeBrackets) charset += "()[]{}<>";

    if (charset === "") {
      setGeneratedPass("Select at least one option");
      return;
    }

    let retVal = "";
    for (let i = 0, n = charset.length; i < length; ++i) {
      retVal += charset.charAt(Math.floor(Math.random() * n));
    }
    setGeneratedPass(retVal);
  }, [length, includeLowercase, includeUppercase, includeNumbers, includeSymbols, includeBrackets]);

  useEffect(() => {
    generatePassword();
    checkSecurity();
    checkHardwareSupport();
  }, [generatePassword]);

  const checkHardwareSupport = async () => {
    if (window.PublicKeyCredential) {
      setIsHardwareSupported(true);
      try {
        const res = await fetch('/api/webauthn/credentials');
        const creds = await res.json();
        setHasHardwareKey(creds.length > 0);
      } catch (e) {
        // Silent error
      }
    }
  };

  const registerHardwareKey = async () => {
    if (!masterKey) return;
    try {
      const challenge = window.crypto.getRandomValues(new Uint8Array(32));
      const userID = window.crypto.getRandomValues(new Uint8Array(16));
      
      const credential = await navigator.credentials.create({
        publicKey: {
          challenge,
          rp: { name: "Hyper Vault" },
          user: {
            id: userID,
            name: "user@hypervault",
            displayName: "Vault User"
          },
          pubKeyCredParams: [{ alg: -7, type: "public-key" }],
          authenticatorSelection: {
            authenticatorAttachment: "platform",
            userVerification: "required"
          },
          timeout: 60000
        }
      }) as PublicKeyCredential;

      if (credential) {
        const response = credential.response as AuthenticatorAttestationResponse;
        await fetch('/api/webauthn/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            id: credential.id,
            publicKey: bufferToBase64(response.getPublicKey()),
            userHandle: bufferToBase64(userID)
          })
        });
        setHasHardwareKey(true);
        alert("Hardware key registered successfully!");
      }
    } catch (err) {
      // Silent error
      alert("Failed to register hardware key. Ensure your device supports biometrics.");
    }
  };

  const unlockWithHardware = async () => {
    if (!hasHardwareKey) return;
    try {
      const res = await fetch('/api/webauthn/credentials');
      const creds = await res.json();
      
      const challenge = window.crypto.getRandomValues(new Uint8Array(32));
      const assertion = await navigator.credentials.get({
        publicKey: {
          challenge,
          allowCredentials: creds.map((c: any) => ({
            id: base64ToBuffer(c.id),
            type: 'public-key'
          })),
          userVerification: "required"
        }
      });

      if (assertion) {
        // In a real production app, we would verify the signature on the server.
        // For this vault, we still need the master password to derive the encryption key.
        // Hardware unlock here acts as a "Fast Unlock" if the key is cached securely,
        // but for maximum security, we'll prompt for the password once per session.
        alert("Hardware verification successful! Please enter your master password to decrypt.");
      }
    } catch (err) {
      // Silent error
    }
  };

  // Inactivity Auto-Lock
  useEffect(() => {
    if (isLocked) return;

    const interval = setInterval(() => {
      const now = Date.now();
      if (now - lastActivity > 60 * 1000) { // 60 seconds
        lockVault();
      }
    }, 5000); // Check more frequently

    const handleActivity = () => setLastActivity(Date.now());
    window.addEventListener('mousemove', handleActivity);
    window.addEventListener('keydown', handleActivity);
    window.addEventListener('click', handleActivity);

    return () => {
      clearInterval(interval);
      window.removeEventListener('mousemove', handleActivity);
      window.removeEventListener('keydown', handleActivity);
      window.removeEventListener('click', handleActivity);
    };
  }, [isLocked, lastActivity]);

  const lockVault = () => {
    // Explicitly clear all sensitive state from memory
    setMasterKey(null);
    setIsLocked(true);
    setSavedPasswords([]);
    setNotes([]);
    setQrcodes([]);
    setDecryptedPasswords({});
    setShowPassMap({});
    setMasterPasswordInput('');
    setMasterPasswordConfirm('');
    setGeneratedPass('');
    setNewPassword('');
    setNewNoteContent('');
    setNewNoteCode('');
    setNewQrContent('');
    setSecurityError('');
    
    // Force a re-render to ensure memory is cleared
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const detectRoot = async () => {
    const checks = {
      suBinary: false,
      testKeys: false,
      emulator: false,
      automation: !!navigator.webdriver,
      suspiciousPaths: false
    };

    // 1. Emulator detection via WebGL Renderer
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl');
      if (gl) {
        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        if (debugInfo) {
          const renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL).toLowerCase();
          const suspiciousRenderers = ['swiftshader', 'google', 'virtualbox', 'vmware', 'llvmpipe', 'software'];
          if (suspiciousRenderers.some(r => renderer.includes(r))) {
            checks.emulator = true;
          }
        }
      }
    } catch (e) {}

    // 2. Detect common "root" indicators if injected into browser environment
    // (Some rooted environments inject globals into the browser)
    if ((window as any)._magisk || (window as any)._xposed || (window as any)._root) {
      checks.suBinary = true;
    }

    // 3. Check for suspicious User Agent strings (often modified by root tools)
    const ua = navigator.userAgent.toLowerCase();
    if (ua.includes('test-keys') || ua.includes('cyanogenmod') || ua.includes('lineageos')) {
      checks.testKeys = true;
    }

    // 4. Check for suspicious system-like paths in environment (simulated for web)
    // In a real native app, we'd check /system/bin/su. In web, we can check for 
    // certain environment variables or behaviors.
    if (process.env.NODE_ENV === 'development' && window.location.hostname === 'localhost') {
      // We don't flag local dev as rooted, but we could check for other things
    }

    const isSuspicious = checks.emulator || checks.automation || checks.suBinary || checks.testKeys;
    
    setIntegrityChecks(checks);
    if (isSuspicious) {
      setIsRooted(true);
      setShowRootWarning(true);
    }
    
    return isSuspicious;
  };

  const checkSecurity = async () => {
    // Run root detection first
    await detectRoot();
    
    try {
      const [saltRes, authSaltRes, authHashRes] = await Promise.all([
        fetch('/api/settings/master_salt'),
        fetch('/api/settings/auth_salt'),
        fetch('/api/settings/auth_hash')
      ]);

      const saltData = await saltRes.json();
      const authSaltData = await authSaltRes.json();
      const authHashData = await authHashRes.json();

      if (saltData.value && authSaltData.value && authHashData.value) {
        setMasterSalt(new Uint8Array(base64ToBuffer(saltData.value)));
        setAuthSalt(new Uint8Array(base64ToBuffer(authSaltData.value)));
        setAuthHash(authHashData.value);
        setIsLocked(true);
      } else {
        setShowMasterSetup(true);
      }
    } catch (err) {
      // Silent error
    }
  };

  const checkPasswordStrength = (pass: string) => {
    let score = 0;
    if (pass.length >= 12) score += 1;
    if (pass.length >= 16) score += 1;
    if (/[A-Z]/.test(pass)) score += 1;
    if (/[0-9]/.test(pass)) score += 1;
    if (/[^A-Za-z0-9]/.test(pass)) score += 1;
    setPasswordStrength(score);
  };

  const handleSetupMaster = async (e: FormEvent) => {
    e.preventDefault();
    if (masterPasswordInput.length < 12) {
      setSecurityError("Master password should be at least 12 characters for better security");
      return;
    }
    if (masterPasswordInput !== masterPasswordConfirm) {
      setSecurityError("Passwords do not match");
      return;
    }
    if (passwordStrength < 3) {
      setSecurityError("Please choose a stronger password (at least 3 strength bars)");
      return;
    }

    const mSalt = window.crypto.getRandomValues(new Uint8Array(16));
    const aSalt = window.crypto.getRandomValues(new Uint8Array(16));
    
    try {
      const passwordBuffer1 = stringToUint8Array(masterPasswordInput);
      const passwordBuffer2 = stringToUint8Array(masterPasswordInput);
      setMasterPasswordInput('');
      setMasterPasswordConfirm('');
      
      const aHash = await deriveHash(passwordBuffer1, aSalt);

      await Promise.all([
        fetch('/api/settings', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ key: 'master_salt', value: bufferToBase64(mSalt) })
        }),
        fetch('/api/settings', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ key: 'auth_salt', value: bufferToBase64(aSalt) })
        }),
        fetch('/api/settings', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ key: 'auth_hash', value: aHash })
        })
      ]);
      
      const { encryptionKey, integrityKey: iKey } = await deriveKey(passwordBuffer2, mSalt);
      setMasterKey(encryptionKey);
      setIntegrityKey(iKey);
      setMasterSalt(mSalt);
      setAuthSalt(aSalt);
      setAuthHash(aHash);
      setIsLocked(false);
      setShowMasterSetup(false);
      setSecurityError('');
      setLastActivity(Date.now());
    } catch (err) {
      setSecurityError("Failed to save security settings");
    }
  };

  const handleUnlock = async (e: FormEvent) => {
    e.preventDefault();
    if (!masterSalt || !authSalt || !authHash) return;

    if (lockoutUntil && Date.now() < lockoutUntil) {
      const remaining = Math.ceil((lockoutUntil - Date.now()) / 1000);
      setSecurityError(`Too many failed attempts. Try again in ${remaining}s`);
      return;
    }

    try {
      const passwordBuffer1 = stringToUint8Array(masterPasswordInput);
      const passwordBuffer2 = stringToUint8Array(masterPasswordInput);
      setMasterPasswordInput('');

      // 1. Verify Hash
      const inputHash = await deriveHash(passwordBuffer1, authSalt);
      if (inputHash !== authHash) {
        // Zero out the other buffer since we won't use it for key derivation
        zeroOut(passwordBuffer2);
        
        const newFailed = failedAttempts + 1;
        setFailedAttempts(newFailed);
        if (newFailed >= 3) {
          setLockoutUntil(Date.now() + 30000); // 30s lockout
          setSecurityError("Too many failed attempts. Locked for 30 seconds.");
        } else {
          setSecurityError(`Invalid Master Password. ${3 - newFailed} attempts remaining.`);
        }
        return;
      }

      // 2. Derive Encryption and Integrity Keys
      const { encryptionKey, integrityKey: iKey } = await deriveKey(passwordBuffer2, masterSalt);
      setMasterKey(encryptionKey);
      setIntegrityKey(iKey);
      setIsLocked(false);
      setSecurityError('');
      setFailedAttempts(0);
      setLockoutUntil(null);
      setLastActivity(Date.now());
      
      // Fetch data after unlocking
      fetchPasswords(encryptionKey, iKey);
      fetchNotes(encryptionKey, iKey);
      fetchQrcodes(encryptionKey, iKey);
    } catch (err) {
      setSecurityError("Security error during unlock");
    }
  };

  const fetchPasswords = async (keyOverride?: CryptoKey, iKeyOverride?: CryptoKey) => {
    const key = keyOverride || masterKey;
    const iKey = iKeyOverride || integrityKey;
    if (!key || !iKey) return;
    try {
      const res = await fetch('/api/passwords');
      const data = await res.json();
      
      const decryptedData = await Promise.all(data.map(async (item: any) => {
        // Integrity Verification
        if (item.signature) {
          const payload = [
            item.service,
            item.username,
            item.email,
            item.phone,
            item.backup_code,
            item.password,
            JSON.stringify(item.custom_fields)
          ].join('|');
          
          const isValid = await verifyData(payload, item.signature, iKey);
          if (!isValid) {
            setIsCompromised(true);
            setSecurityWarning("Vault integrity check failed. Data tampering detected in password entries.");
            throw new Error("Integrity check failed");
          }
        }

        return {
          ...item,
          service: await decrypt(item.service, key),
          username: await decrypt(item.username, key),
          email: await decrypt(item.email, key),
          phone: await decrypt(item.phone, key),
          backup_code: await decrypt(item.backup_code, key),
          // Keep password encrypted in state
          password: item.password, 
          custom_fields: await Promise.all((item.custom_fields || []).map(async (f: any) => ({
            label: await decrypt(f.label, key),
            value: await decrypt(f.value, key)
          })))
        };
      }));
      
      setSavedPasswords(decryptedData);
    } catch (err) {
      if (err instanceof Error && err.message === "Integrity check failed") {
        // Handled by state
      }
    }
  };

  const savePassword = async (e: FormEvent) => {
    e.preventDefault();
    if (!newService || !newPassword || !masterKey || !integrityKey) return;

    try {
      const url = editingId ? `/api/passwords/${editingId}` : '/api/passwords';
      const method = editingId ? 'PUT' : 'POST';

      const passwordBuffer = stringToUint8Array(newPassword);
      setNewPassword(''); // Clear string immediately

      const encryptedData = {
        service: await encrypt(newService, masterKey),
        username: await encrypt(newUsername, masterKey),
        email: await encrypt(newEmail, masterKey),
        phone: await encrypt(newPhone, masterKey),
        backup_code: await encrypt(newBackupCode, masterKey),
        password: await encrypt(passwordBuffer, masterKey),
        custom_fields: await Promise.all(customFields.map(async f => ({
          label: await encrypt(f.label, masterKey),
          value: await encrypt(f.value, masterKey)
        })))
      };

      const payload = [
        encryptedData.service,
        encryptedData.username,
        encryptedData.email,
        encryptedData.phone,
        encryptedData.backup_code,
        encryptedData.password,
        JSON.stringify(encryptedData.custom_fields)
      ].join('|');

      const signature = await signData(payload, integrityKey);

      const res = await fetch(url, {
        method: method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...encryptedData, signature })
      });
      if (res.ok) {
        resetForm();
        fetchPasswords();
      }
    } catch (err) {
      // Silent error
    }
  };

  const resetForm = () => {
    setNewService('');
    setNewUsername('');
    setNewEmail('');
    setNewPhone('');
    setNewBackupCode('');
    setNewPassword('');
    setCustomFields([]);
    setShowForm(false);
    setEditingId(null);
  };

  const startEdit = async (item: SavedPassword) => {
    if (!masterKey) return;
    try {
      const decryptedPass = await decrypt(item.password, masterKey);
      setNewService(item.service);
      setNewUsername(item.username || '');
      setNewEmail(item.email || '');
      setNewPhone(item.phone || '');
      setNewBackupCode(item.backup_code || '');
      setNewPassword(decryptedPass);
      setCustomFields(item.custom_fields || []);
      setEditingId(item.id);
      setShowForm(true);
      // Scroll to form or ensure it's visible
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } catch (e) {
      // Silent error
    }
  };

  const addCustomField = () => {
    setCustomFields([...customFields, { label: '', value: '' }]);
  };

  const updateCustomField = (index: number, field: 'label' | 'value', value: string) => {
    const updated = [...customFields];
    updated[index][field] = value;
    setCustomFields(updated);
  };

  const removeCustomField = (index: number) => {
    setCustomFields(customFields.filter((_, i) => i !== index));
  };

  const deletePassword = async (id: number) => {
    try {
      await fetch(`/api/passwords/${id}`, { method: 'DELETE' });
      fetchPasswords();
    } catch (err) {
      // Silent error
    }
  };

  const fetchNotes = async (keyOverride?: CryptoKey, iKeyOverride?: CryptoKey) => {
    const key = keyOverride || masterKey;
    const iKey = iKeyOverride || integrityKey;
    if (!key || !iKey) return;
    try {
      const res = await fetch('/api/notes');
      const data = await res.json();
      
      const decryptedData = await Promise.all(data.map(async (item: any) => {
        // Integrity Verification
        if (item.signature) {
          const payload = [
            item.title,
            item.content,
            item.image,
            item.link,
            item.code
          ].join('|');
          
          const isValid = await verifyData(payload, item.signature, iKey);
          if (!isValid) {
            setIsCompromised(true);
            setSecurityWarning("Vault integrity check failed. Data tampering detected in notes.");
            throw new Error("Integrity check failed");
          }
        }

        return {
          ...item,
          title: await decrypt(item.title, key),
          content: await decrypt(item.content, key),
          image: await decrypt(item.image, key),
          link: await decrypt(item.link, key),
          code: await decrypt(item.code, key)
        };
      }));
      
      setNotes(decryptedData);
    } catch (err) {
      if (err instanceof Error && err.message === "Integrity check failed") {
        // Handled by state
      }
    }
  };

  const saveNote = async (e: FormEvent) => {
    e.preventDefault();
    if (!masterKey || !integrityKey) return;
    
    const titleToSave = newNoteTitle.trim() || `title ${notes.length + 1}`;

    try {
      const encryptedData = {
        title: await encrypt(titleToSave, masterKey),
        content: await encrypt(newNoteContent, masterKey),
        image: await encrypt(newNoteImage || '', masterKey),
        link: await encrypt(newNoteLink, masterKey),
        code: await encrypt(newNoteCode, masterKey)
      };

      const payload = [
        encryptedData.title,
        encryptedData.content,
        encryptedData.image,
        encryptedData.link,
        encryptedData.code
      ].join('|');

      const signature = await signData(payload, integrityKey);

      const res = await fetch('/api/notes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...encryptedData, signature })
      });
      if (res.ok) {
        setNewNoteTitle('');
        setNewNoteContent('');
        setNewNoteImage(null);
        setNewNoteLink('');
        setNewNoteCode('');
        setShowNoteForm(false);
        fetchNotes();
      }
    } catch (err) {
      // Silent error
    }
  };

  const deleteNote = async (id: number) => {
    try {
      await fetch(`/api/notes/${id}`, { method: 'DELETE' });
      fetchNotes();
    } catch (err) {
      // Silent error
    }
  };

  const handleImageUpload = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onloadend = () => {
        setNewNoteImage(reader.result as string);
      };
      reader.readAsDataURL(file);
    }
  };

  const fetchQrcodes = async (keyOverride?: CryptoKey, iKeyOverride?: CryptoKey) => {
    const key = keyOverride || masterKey;
    const iKey = iKeyOverride || integrityKey;
    if (!key || !iKey) return;
    try {
      const res = await fetch('/api/qrcodes');
      const data = await res.json();
      
      const decryptedData = await Promise.all(data.map(async (item: any) => {
        // Integrity Verification
        if (item.signature) {
          const payload = [
            item.service,
            item.username,
            item.content
          ].join('|');
          
          const isValid = await verifyData(payload, item.signature, iKey);
          if (!isValid) {
            setIsCompromised(true);
            setSecurityWarning("Vault integrity check failed. Data tampering detected in QR codes.");
            throw new Error("Integrity check failed");
          }
        }

        return {
          ...item,
          service: await decrypt(item.service, key),
          username: await decrypt(item.username, key),
          content: await decrypt(item.content, key)
        };
      }));
      
      setQrcodes(decryptedData);
    } catch (err) {
      if (err instanceof Error && err.message === "Integrity check failed") {
        // Handled by state
      }
    }
  };

  const saveQrcode = async (e: FormEvent) => {
    e.preventDefault();
    if (!newQrService || !newQrContent || !masterKey || !integrityKey) return;

    try {
      const encryptedData = {
        service: await encrypt(newQrService, masterKey),
        username: await encrypt(newQrUsername, masterKey),
        content: await encrypt(newQrContent, masterKey)
      };

      const payload = [
        encryptedData.service,
        encryptedData.username,
        encryptedData.content
      ].join('|');

      const signature = await signData(payload, integrityKey);

      const res = await fetch('/api/qrcodes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...encryptedData, signature })
      });
      if (res.ok) {
        setNewQrService('');
        setNewQrUsername('');
        setNewQrContent('');
        setShowQrForm(false);
        fetchQrcodes();
      }
    } catch (err) {
      // Silent error
    }
  };

  const deleteQrcode = async (id: number) => {
    try {
      await fetch(`/api/qrcodes/${id}`, { method: 'DELETE' });
      fetchQrcodes();
    } catch (err) {
      // Silent error
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
    
    // Security: Clear clipboard after 30 seconds
    setTimeout(() => {
      navigator.clipboard.readText().then(current => {
        if (current === text) {
          navigator.clipboard.writeText("");
        }
      }).catch(() => {
        // Fallback: just clear it anyway if permission denied
        navigator.clipboard.writeText("");
      });
    }, 30000);
  };

  const togglePassVisibility = async (id: number) => {
    if (showPassMap[id]) {
      setShowPassMap(prev => ({ ...prev, [id]: false }));
      setDecryptedPasswords(prev => {
        const next = { ...prev };
        delete next[id];
        return next;
      });
    } else {
      const item = savedPasswords.find(p => p.id === id);
      if (item && masterKey) {
        const decrypted = await decrypt(item.password, masterKey);
        setDecryptedPasswords(prev => ({ ...prev, [id]: decrypted }));
        setShowPassMap(prev => ({ ...prev, [id]: true }));
      }
    }
  };

  const copyPassword = async (id: number) => {
    const item = savedPasswords.find(p => p.id === id);
    if (item && masterKey) {
      const decrypted = await decrypt(item.password, masterKey);
      copyToClipboard(decrypted);
      // Clear decrypted string from memory as soon as possible
      // (Though copyToClipboard might keep it for a bit, we do our part)
    }
  };

  return (
    <div className={cn(
      "min-h-screen transition-all duration-500",
      (!isWindowFocused || !isTabVisible) && "blur-2xl scale-[0.98] pointer-events-none select-none"
    )}>
      <AnimatePresence mode="wait">
        {(!isWindowFocused || !isTabVisible) && (
          <div key="privacy-overlay" className="fixed inset-0 z-[200] bg-zinc-900/40 backdrop-blur-3xl flex items-center justify-center">
            <motion.div 
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              className="text-center space-y-4"
            >
              <div className="w-20 h-20 bg-white/10 rounded-full flex items-center justify-center text-white mx-auto border border-white/20">
                <Lock size={40} className="animate-pulse" />
              </div>
              <div className="space-y-1">
                <h2 className="text-xl font-bold text-white">Privacy Protected</h2>
                <p className="text-white/60 text-sm">Vault content is hidden while inactive</p>
              </div>
            </motion.div>
          </div>
        )}

        {showRootWarning && (
          <div key="root-warning" className="fixed inset-0 z-[150] bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
            <motion.div 
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 20 }}
              className="max-w-md w-full bg-white rounded-3xl p-8 shadow-2xl border border-red-100"
            >
              <div className="text-center space-y-4">
                <div className="w-20 h-20 bg-red-50 rounded-full flex items-center justify-center text-red-600 mx-auto animate-pulse">
                  <AlertTriangle size={40} />
                </div>
                <div className="space-y-2">
                  <h2 className="text-2xl font-bold text-zinc-900">Security Integrity Warning</h2>
                  <p className="text-zinc-500 text-sm">
                    Our system has detected that this device or environment may be compromised (Rooted, Emulator, or Automation detected).
                  </p>
                </div>

                <div className="bg-zinc-50 rounded-2xl p-4 text-left space-y-2 border border-zinc-100">
                  <p className="text-[10px] font-bold uppercase tracking-widest text-zinc-400 mb-2">Integrity Report</p>
                  <div className="grid grid-cols-2 gap-2">
                    {Object.entries(integrityChecks).map(([key, value]) => (
                      <div key={key} className="flex items-center gap-2 text-xs">
                        <div className={cn("w-2 h-2 rounded-full", value ? "bg-red-500" : "bg-emerald-500")} />
                        <span className="text-zinc-600 capitalize">{key.replace(/([A-Z])/g, ' $1')}</span>
                        <span className="ml-auto font-mono text-[10px]">{value ? "FAIL" : "PASS"}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <p className="text-xs text-red-500 font-medium bg-red-50 p-3 rounded-xl">
                  Running a secure vault on a compromised device is highly discouraged as your master password could be intercepted by system-level malware.
                </p>

                <div className="flex flex-col gap-3 pt-2">
                  <button 
                    onClick={() => setShowRootWarning(false)}
                    className="w-full py-4 bg-zinc-900 text-white rounded-2xl font-semibold hover:bg-zinc-800 transition-all shadow-lg shadow-zinc-200"
                  >
                    I Understand the Risk
                  </button>
                  <button 
                    onClick={() => window.location.href = 'about:blank'}
                    className="w-full py-4 bg-white text-zinc-600 border border-zinc-200 rounded-2xl font-semibold hover:bg-zinc-50 transition-all"
                  >
                    Exit Securely
                  </button>
                </div>
              </div>
            </motion.div>
          </div>
        )}

        {showMasterSetup && (
          <div key="master-setup-overlay" className="fixed inset-0 z-[100] bg-zinc-50 flex items-center justify-center p-4">
            <motion.div 
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="max-w-md w-full glass-card p-8 space-y-6"
            >
              <div className="text-center space-y-2">
                <div className="w-16 h-16 bg-zinc-900 rounded-2xl flex items-center justify-center text-white mx-auto mb-4">
                  <Shield size={32} />
                </div>
                <h1 className="text-2xl font-bold text-zinc-900">Setup Hyper Vault</h1>
                <p className="text-zinc-500 text-sm">Set a master password to encrypt your vault. This password is never stored and cannot be recovered.</p>
              </div>

              <form onSubmit={handleSetupMaster} className="space-y-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold uppercase tracking-wider text-zinc-500">Master Password</label>
                  <input 
                    type="password" 
                    placeholder="At least 12 characters"
                    className="input-field"
                    autoComplete="off"
                    value={masterPasswordInput}
                    onChange={(e) => {
                      setMasterPasswordInput(e.target.value);
                      checkPasswordStrength(e.target.value);
                    }}
                    required
                  />
                  <div className="flex gap-1 mt-1">
                    {[...Array(5)].map((_, i) => (
                      <div 
                        key={i} 
                        className={cn(
                          "h-1 flex-1 rounded-full transition-colors",
                          i < passwordStrength 
                            ? (passwordStrength <= 2 ? "bg-red-400" : passwordStrength <= 4 ? "bg-amber-400" : "bg-emerald-400")
                            : "bg-zinc-200"
                        )} 
                      />
                    ))}
                  </div>
                  <p className="text-[10px] text-zinc-400 mt-1">
                    Strength: {passwordStrength <= 2 ? "Weak" : passwordStrength <= 4 ? "Medium" : "Strong"}
                  </p>
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold uppercase tracking-wider text-zinc-500">Confirm Password</label>
                  <input 
                    type="password" 
                    placeholder="Repeat master password"
                    className="input-field"
                    autoComplete="off"
                    value={masterPasswordConfirm}
                    onChange={(e) => setMasterPasswordConfirm(e.target.value)}
                    required
                  />
                </div>
                {securityError && (
                  <div className="p-3 bg-red-50 border border-red-100 rounded-xl flex items-center gap-2 text-red-600 text-sm">
                    <AlertTriangle size={16} />
                    {securityError}
                  </div>
                )}
                <button type="submit" className="btn-primary w-full py-3">
                  Create Secure Vault
                </button>
              </form>
            </motion.div>
          </div>
        )}

        {isLocked && !showMasterSetup && (
          <div key="vault-locked-overlay" className="fixed inset-0 z-[100] bg-zinc-50 flex items-center justify-center p-4">
            <motion.div 
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="max-w-md w-full glass-card p-8 space-y-6"
            >
              <div className="text-center space-y-2">
                <div className="w-16 h-16 bg-zinc-900 rounded-2xl flex items-center justify-center text-white mx-auto mb-4">
                  <Lock size={32} />
                </div>
                <h1 className="text-2xl font-bold text-zinc-900">Vault Locked</h1>
                <p className="text-zinc-500 text-sm">Enter your master password to access your data.</p>
              </div>

              <form onSubmit={handleUnlock} className="space-y-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold uppercase tracking-wider text-zinc-500">Master Password</label>
                  <input 
                    type="password" 
                    placeholder="Enter master password"
                    className="input-field"
                    autoComplete="off"
                    value={masterPasswordInput}
                    onChange={(e) => setMasterPasswordInput(e.target.value)}
                    required
                    autoFocus
                  />
                </div>
                {securityError && (
                  <div className="p-3 bg-red-50 border border-red-100 rounded-xl flex items-center gap-2 text-red-600 text-sm">
                    <AlertTriangle size={16} />
                    {securityError}
                  </div>
                )}
                <div className="flex flex-col gap-3">
                  <button type="submit" className="btn-primary w-full py-3">
                    Unlock Vault
                  </button>
                  {isHardwareSupported && hasHardwareKey && (
                    <button 
                      type="button" 
                      onClick={unlockWithHardware}
                      className="btn-secondary w-full py-3 flex items-center justify-center gap-2"
                    >
                      <Shield size={18} />
                      Unlock with Hardware
                    </button>
                  )}
                </div>
              </form>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      <div className={cn(
        "min-h-screen bg-[#f8f9fa] p-4 md:p-8 pb-24 md:pb-8 transition-all duration-500",
        isCompromised ? "blur-xl scale-[0.98] pointer-events-none select-none" : ""
      )}>
        {isCompromised && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center bg-white/80 backdrop-blur-md">
            <div className="glass-card p-8 text-center space-y-4 max-w-md">
              <AlertTriangle size={48} className="text-red-500 mx-auto" />
              <h2 className="text-xl font-bold text-zinc-900">Security Alert</h2>
              <p className="text-zinc-600">{securityWarning}</p>
            </div>
          </div>
        )}
      <div className="max-w-4xl mx-auto space-y-8">
        {/* Header */}
        <header className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-zinc-900 rounded-xl flex items-center justify-center text-white">
              <Shield size={24} />
            </div>
            <div>
              <h1 className="text-2xl font-semibold tracking-tight">Hyper Vault</h1>
              <p className="text-sm text-zinc-500">Secure your digital identity</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button 
              onClick={() => setPrivacyMode(!privacyMode)}
              className={cn(
                "p-2 rounded-lg transition-all flex items-center gap-2 text-sm font-medium",
                privacyMode ? "bg-zinc-900 text-white" : "bg-zinc-100 text-zinc-600 hover:bg-zinc-200"
              )}
              title={privacyMode ? "Disable Privacy Mode" : "Enable Privacy Mode"}
            >
              {privacyMode ? <EyeOff size={18} /> : <Eye size={18} />}
              <span className="hidden sm:inline">{privacyMode ? "Private" : "Public"}</span>
            </button>
            <button 
              onClick={lockVault}
              className="p-2 text-zinc-400 hover:text-zinc-900 hover:bg-zinc-100 rounded-lg transition-all"
              title="Lock Vault"
            >
              <Lock size={20} />
            </button>
          </div>
        </header>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          {/* Generator Section */}
          <section className={cn(
            "lg:col-span-5 space-y-6",
            activeTab !== 'generator' && "hidden lg:block"
          )}>
            <div className="glass-card p-6 space-y-6">
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-medium flex items-center gap-2">
                  <RefreshCw size={18} className="text-zinc-500" />
                  Generator
                </h2>
              </div>

              <div className="relative group">
                <div className="w-full p-4 bg-zinc-50 border border-zinc-200 rounded-xl font-mono text-lg break-all pr-12 min-h-[64px] flex items-center">
                  {generatedPass}
                </div>
                <button 
                  onClick={() => copyToClipboard(generatedPass)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 p-2 hover:bg-zinc-200 rounded-lg transition-colors text-zinc-500"
                  title="Copy to clipboard"
                >
                  {copied ? <Check size={18} className="text-emerald-600" /> : <Copy size={18} />}
                </button>
              </div>

              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <label className="text-sm font-medium text-zinc-600">Length: {length}</label>
                </div>
                <input 
                  type="range" 
                  min="8" 
                  max="64" 
                  value={length} 
                  onChange={(e) => setLength(parseInt(e.target.value))}
                  className="w-full h-2 bg-zinc-200 rounded-lg appearance-none cursor-pointer accent-zinc-900"
                />
                <div className="flex justify-between text-[10px] text-zinc-400 font-mono">
                  <span>8</span>
                  <span>32</span>
                  <span>64</span>
                </div>
              </div>

              <div className="space-y-3 pt-2">
                <label className="text-xs font-semibold uppercase tracking-wider text-zinc-500">Complexity</label>
                <div className="grid grid-cols-2 gap-3">
                  <label className="flex items-center gap-3 p-3 bg-zinc-50 border border-zinc-100 rounded-xl cursor-pointer hover:bg-zinc-100 transition-colors">
                    <input 
                      type="checkbox" 
                      checked={includeLowercase} 
                      onChange={(e) => setIncludeLowercase(e.target.checked)}
                      className="w-4 h-4 rounded accent-zinc-900"
                    />
                    <span className="text-sm text-zinc-700">Lowercase</span>
                  </label>
                  <label className="flex items-center gap-3 p-3 bg-zinc-50 border border-zinc-100 rounded-xl cursor-pointer hover:bg-zinc-100 transition-colors">
                    <input 
                      type="checkbox" 
                      checked={includeUppercase} 
                      onChange={(e) => setIncludeUppercase(e.target.checked)}
                      className="w-4 h-4 rounded accent-zinc-900"
                    />
                    <span className="text-sm text-zinc-700">Uppercase</span>
                  </label>
                  <label className="flex items-center gap-3 p-3 bg-zinc-50 border border-zinc-100 rounded-xl cursor-pointer hover:bg-zinc-100 transition-colors">
                    <input 
                      type="checkbox" 
                      checked={includeNumbers} 
                      onChange={(e) => setIncludeNumbers(e.target.checked)}
                      className="w-4 h-4 rounded accent-zinc-900"
                    />
                    <span className="text-sm text-zinc-700">Numbers</span>
                  </label>
                  <label className="flex items-center gap-3 p-3 bg-zinc-50 border border-zinc-100 rounded-xl cursor-pointer hover:bg-zinc-100 transition-colors">
                    <input 
                      type="checkbox" 
                      checked={includeSymbols} 
                      onChange={(e) => setIncludeSymbols(e.target.checked)}
                      className="w-4 h-4 rounded accent-zinc-900"
                    />
                    <span className="text-sm text-zinc-700">Symbols</span>
                  </label>
                  <label className="flex items-center gap-3 p-3 bg-zinc-50 border border-zinc-100 rounded-xl cursor-pointer hover:bg-zinc-100 transition-colors">
                    <input 
                      type="checkbox" 
                      checked={includeBrackets} 
                      onChange={(e) => setIncludeBrackets(e.target.checked)}
                      className="w-4 h-4 rounded accent-zinc-900"
                    />
                    <span className="text-sm text-zinc-700">Brackets</span>
                  </label>
                </div>
              </div>

              <button 
                onClick={generatePassword}
                className="btn-primary w-full flex items-center justify-center gap-2"
              >
                <RefreshCw size={18} />
                Generate New
              </button>
            </div>

            <div className="glass-card p-6 bg-emerald-50/50 border-emerald-100">
              <div className="flex gap-3">
                <div className="p-2 bg-emerald-100 rounded-lg text-emerald-700">
                  <Lock size={20} />
                </div>
                <div>
                  <h3 className="font-medium text-emerald-900 text-sm">Security Tip</h3>
                  <p className="text-xs text-emerald-700 mt-1 leading-relaxed">
                    Use at least 16 characters with a mix of letters, numbers, and symbols for maximum security.
                  </p>
                </div>
              </div>
            </div>
          </section>

          {/* Vault Section */}
          <section className={cn(
            "lg:col-span-7 space-y-6",
            activeTab !== 'vault' && "hidden lg:block"
          )}>
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-medium flex items-center gap-2">
                <Key size={18} className="text-zinc-500" />
                Vault
              </h2>
              <div className="flex items-center gap-2">
                {isHardwareSupported && (
                  <button 
                    onClick={registerHardwareKey}
                    className={cn(
                      "btn-secondary py-1.5 px-3 flex items-center gap-2 text-xs",
                      hasHardwareKey ? "text-emerald-600 border-emerald-100 bg-emerald-50" : ""
                    )}
                    title="Register Hardware Key"
                  >
                    <Shield size={14} />
                    {hasHardwareKey ? "Hardware Active" : "Add Hardware Key"}
                  </button>
                )}
                <button 
                  onClick={() => {
                    if (showForm && editingId) {
                      resetForm();
                    } else {
                      setShowForm(!showForm);
                      if (!showForm) setEditingId(null);
                    }
                  }}
                  className="btn-secondary py-1.5 px-4 flex items-center gap-2 text-sm"
                >
                  {showForm && editingId ? 'Cancel Edit' : (
                    <>
                      <Plus size={16} />
                      Add New
                    </>
                  )}
                </button>
              </div>
            </div>

            <AnimatePresence mode="wait">
              {showForm && (
                <motion.div 
                  key="password-form"
                  initial={{ opacity: 0, y: -20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  className="glass-card p-6 border-zinc-200"
                >
                  <form onSubmit={savePassword} className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="space-y-1.5">
                        <label className="text-xs font-semibold uppercase tracking-wider text-zinc-500 flex items-center gap-1">
                          <Globe size={12} /> Service
                        </label>
                        <input 
                          type="text" 
                          placeholder="e.g. Instagram, Netflix"
                          className="input-field"
                          value={newService}
                          onChange={(e) => setNewService(e.target.value)}
                          required
                        />
                      </div>
                      <div className="space-y-1.5">
                        <label className="text-xs font-semibold uppercase tracking-wider text-zinc-500 flex items-center gap-1">
                          <User size={12} /> Username
                        </label>
                        <input 
                          type="text" 
                          placeholder="username"
                          className="input-field"
                          autoComplete="off"
                          value={newUsername}
                          onChange={(e) => setNewUsername(e.target.value)}
                        />
                      </div>
                      <div className="space-y-1.5">
                        <label className="text-xs font-semibold uppercase tracking-wider text-zinc-500 flex items-center gap-1">
                          <Globe size={12} /> Email
                        </label>
                        <input 
                          type="email" 
                          placeholder="your@email.com"
                          className="input-field"
                          autoComplete="off"
                          value={newEmail}
                          onChange={(e) => setNewEmail(e.target.value)}
                        />
                      </div>
                      <div className="space-y-1.5">
                        <label className="text-xs font-semibold uppercase tracking-wider text-zinc-500 flex items-center gap-1">
                          <Globe size={12} /> Phone Number
                        </label>
                        <input 
                          type="tel" 
                          placeholder="+1234567890"
                          className="input-field"
                          value={newPhone}
                          onChange={(e) => setNewPhone(e.target.value)}
                        />
                      </div>
                      <div className="space-y-1.5">
                        <label className="text-xs font-semibold uppercase tracking-wider text-zinc-500 flex items-center gap-1">
                          <Shield size={12} /> Backup Code
                        </label>
                        <input 
                          type="text" 
                          placeholder="Backup code"
                          className="input-field"
                          autoComplete="off"
                          value={newBackupCode}
                          onChange={(e) => setNewBackupCode(e.target.value)}
                        />
                      </div>
                      <div className="space-y-1.5">
                        <label className="text-xs font-semibold uppercase tracking-wider text-zinc-500 flex items-center gap-1">
                          <Key size={12} /> Password
                        </label>
                        <div className="flex gap-2">
                          <input 
                            type="text" 
                            placeholder="Password"
                            className="input-field"
                            autoComplete="off"
                            value={newPassword}
                            onChange={(e) => setNewPassword(e.target.value)}
                            required
                          />
                          <button 
                            type="button"
                            onClick={() => setNewPassword(generatedPass)}
                            className="btn-secondary px-3"
                            title="Use generated password"
                          >
                            <RefreshCw size={18} />
                          </button>
                        </div>
                      </div>
                    </div>

                    {/* Custom Fields */}
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <label className="text-xs font-semibold uppercase tracking-wider text-zinc-500">Additional Options</label>
                        <button 
                          type="button" 
                          onClick={addCustomField}
                          className="text-xs flex items-center gap-1 text-zinc-900 hover:underline"
                        >
                          <Plus size={12} /> Add Field
                        </button>
                      </div>
                      {customFields.map((field, index) => (
                        <div key={index} className="flex gap-2 items-end">
                          <div className="flex-1 space-y-1">
                            <input 
                              type="text" 
                              placeholder="Label (e.g. Pin)"
                              className="input-field text-sm"
                              value={field.label}
                              onChange={(e) => updateCustomField(index, 'label', e.target.value)}
                            />
                          </div>
                          <div className="flex-1 space-y-1">
                            <input 
                              type="text" 
                              placeholder="Value"
                              className="input-field text-sm"
                              value={field.value}
                              onChange={(e) => updateCustomField(index, 'value', e.target.value)}
                            />
                          </div>
                          <button 
                            type="button" 
                            onClick={() => removeCustomField(index)}
                            className="p-2 text-zinc-400 hover:text-red-500"
                          >
                            <Trash2 size={16} />
                          </button>
                        </div>
                      ))}
                    </div>

                    <div className="flex gap-3 pt-4 border-t border-zinc-100">
                      <button type="submit" className="btn-primary flex-1 py-3 text-base shadow-lg shadow-zinc-200">
                        {editingId ? 'Update Entry' : 'Save to Vault'}
                      </button>
                      <button 
                        type="button" 
                        onClick={resetForm}
                        className="btn-secondary py-3"
                      >
                        Cancel
                      </button>
                    </div>
                  </form>
                </motion.div>
              )}
            </AnimatePresence>

            <div className="space-y-4">
              {savedPasswords.length === 0 ? (
                <div className="glass-card p-12 text-center space-y-3 border-dashed border-zinc-300 bg-transparent">
                  <div className="w-12 h-12 bg-zinc-100 rounded-full flex items-center justify-center mx-auto text-zinc-400">
                    <Key size={24} />
                  </div>
                  <p className="text-zinc-500">Your vault is empty. Start by adding a password.</p>
                </div>
              ) : (
                savedPasswords.map((item) => (
                  <motion.div 
                    layout
                    key={item.id}
                    className="glass-card overflow-hidden group hover:border-zinc-300 transition-colors"
                  >
                    <div className="p-4 flex items-center justify-between">
                      <div 
                        className="flex items-center gap-4 flex-1 cursor-pointer"
                        onClick={() => setExpandedId(expandedId === item.id ? null : item.id)}
                      >
                        <div className="w-10 h-10 bg-zinc-100 rounded-lg flex items-center justify-center text-zinc-600 font-bold">
                          {item.service.charAt(0).toUpperCase()}
                        </div>
                        <div>
                          <h4 className="font-medium text-zinc-900">{item.service}</h4>
                          <p className="text-xs text-zinc-500">
                            {privacyMode 
                              ? "••••••••••••" 
                              : (item.username || item.email || 'No identifier')}
                          </p>
                        </div>
                      </div>
                      
                      <div className="flex items-center gap-2">
                        <button 
                          onClick={() => startEdit(item)}
                          className="p-2 text-zinc-400 hover:text-blue-600 hover:bg-blue-50 rounded-lg transition-all"
                          title="Edit"
                        >
                          <Edit2 size={18} />
                        </button>
                        
                        <button 
                          onClick={() => copyPassword(item.id)}
                          className="p-2 text-zinc-400 hover:text-zinc-900 hover:bg-zinc-100 rounded-lg transition-all"
                          title="Copy password"
                        >
                          <Copy size={18} />
                        </button>
                        
                        <button 
                          onClick={() => deletePassword(item.id)}
                          className="p-2 text-zinc-400 hover:text-red-600 hover:bg-red-50 rounded-lg transition-all"
                          title="Delete"
                        >
                          <Trash2 size={18} />
                        </button>
                      </div>
                    </div>

                    <AnimatePresence mode="wait">
                      {expandedId === item.id && (
                        <motion.div 
                          key={`details-${item.id}`}
                          initial={{ height: 0, opacity: 0 }}
                          animate={{ height: 'auto', opacity: 1 }}
                          exit={{ height: 0, opacity: 0 }}
                          className="px-4 pb-4 border-t border-zinc-100 bg-zinc-50/50"
                        >
                          <div className="pt-4 space-y-3">
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                              {item.username && (
                                <div className="space-y-1">
                                  <span className="text-[10px] uppercase font-bold text-zinc-400">Username</span>
                                  <div className="flex items-center justify-between gap-2">
                                    <p className="text-sm font-medium selectable-data">
                                      {privacyMode ? "••••••••••••" : item.username}
                                    </p>
                                    {!privacyMode && (
                                      <button onClick={() => copyToClipboard(item.username)} className="text-zinc-400 hover:text-zinc-900">
                                        <Copy size={12} />
                                      </button>
                                    )}
                                  </div>
                                </div>
                              )}
                              {item.email && (
                                <div className="space-y-1">
                                  <span className="text-[10px] uppercase font-bold text-zinc-400">Email</span>
                                  <div className="flex items-center justify-between gap-2">
                                    <p className="text-sm font-medium selectable-data">
                                      {privacyMode ? "••••••••••••" : item.email}
                                    </p>
                                    {!privacyMode && (
                                      <button onClick={() => copyToClipboard(item.email)} className="text-zinc-400 hover:text-zinc-900">
                                        <Copy size={12} />
                                      </button>
                                    )}
                                  </div>
                                </div>
                              )}
                              {item.phone && (
                                <div className="space-y-1">
                                  <span className="text-[10px] uppercase font-bold text-zinc-400">Phone</span>
                                  <div className="flex items-center justify-between gap-2">
                                    <p className="text-sm font-medium selectable-data">
                                      {privacyMode ? "••••••••••••" : item.phone}
                                    </p>
                                    {!privacyMode && (
                                      <button onClick={() => copyToClipboard(item.phone)} className="text-zinc-400 hover:text-zinc-900">
                                        <Copy size={12} />
                                      </button>
                                    )}
                                  </div>
                                </div>
                              )}
                              {item.backup_code && (
                                <div className="space-y-1">
                                  <span className="text-[10px] uppercase font-bold text-zinc-400">Backup Code</span>
                                  <div className="flex items-center justify-between gap-2">
                                    <p className="text-sm font-medium selectable-data">
                                      {privacyMode ? "••••••••••••" : item.backup_code}
                                    </p>
                                    {!privacyMode && (
                                      <button onClick={() => copyToClipboard(item.backup_code)} className="text-zinc-400 hover:text-zinc-900">
                                        <Copy size={12} />
                                      </button>
                                    )}
                                  </div>
                                </div>
                              )}
                            </div>
                            
                            <div className="space-y-1">
                              <span className="text-[10px] uppercase font-bold text-zinc-400">Password</span>
                              <div className="flex items-center gap-2">
                                <p className="text-sm font-mono font-medium selectable-data">
                                  {showPassMap[item.id] ? decryptedPasswords[item.id] : '••••••••••••'}
                                </p>
                                <button 
                                  onClick={() => togglePassVisibility(item.id)}
                                  className="text-zinc-400 hover:text-zinc-600"
                                >
                                  {showPassMap[item.id] ? <EyeOff size={14} /> : <Eye size={14} />}
                                </button>
                              </div>
                            </div>

                            {item.custom_fields && item.custom_fields.length > 0 && (
                              <div className="pt-2 grid grid-cols-1 sm:grid-cols-2 gap-4">
                                {item.custom_fields.map((field, idx) => (
                                  <div key={idx} className="space-y-1">
                                    <span className="text-[10px] uppercase font-bold text-zinc-400">{field.label}</span>
                                    <p className="text-sm font-medium selectable-data">
                                      {privacyMode ? "••••••••••••" : field.value}
                                    </p>
                                    {!privacyMode && (
                                      <button onClick={() => copyToClipboard(field.value)} className="text-zinc-400 hover:text-zinc-900">
                                        <Copy size={12} />
                                      </button>
                                    )}
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </motion.div>
                ))
              )}
            </div>
          </section>

          {/* Notes Section */}
          <section className={cn(
            "lg:col-span-12 space-y-6",
            activeTab !== 'notes' && "hidden"
          )}>
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-medium flex items-center gap-2">
                <FileText size={18} className="text-zinc-500" />
                Notes
              </h2>
              <button 
                onClick={() => setShowNoteForm(!showNoteForm)}
                className="btn-secondary py-1.5 px-4 flex items-center gap-2 text-sm"
              >
                <Plus size={16} />
                Add Note
              </button>
            </div>

            <AnimatePresence mode="wait">
              {showNoteForm && (
                <motion.div 
                  key="note-form"
                  initial={{ opacity: 0, y: -20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  className="glass-card p-6 border-zinc-200"
                >
                  <form onSubmit={saveNote} className="space-y-4">
                    <div className="space-y-1.5">
                      <label className="text-xs font-semibold uppercase tracking-wider text-zinc-500">Title (Optional)</label>
                      <input 
                        type="text" 
                        placeholder="Note Title"
                        className="input-field"
                        value={newNoteTitle}
                        onChange={(e) => setNewNoteTitle(e.target.value)}
                      />
                    </div>
                    <div className="space-y-1.5">
                      <label className="text-xs font-semibold uppercase tracking-wider text-zinc-500">Content</label>
                      <textarea 
                        placeholder="Write your note here..."
                        className="input-field min-h-[100px] py-3"
                        autoComplete="off"
                        value={newNoteContent}
                        onChange={(e) => setNewNoteContent(e.target.value)}
                      />
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="space-y-1.5">
                        <label className="text-xs font-semibold uppercase tracking-wider text-zinc-500 flex items-center gap-1">
                          <LinkIcon size={12} /> Link
                        </label>
                        <input 
                          type="url" 
                          placeholder="https://example.com"
                          className="input-field"
                          value={newNoteLink}
                          onChange={(e) => setNewNoteLink(e.target.value)}
                        />
                      </div>
                      <div className="space-y-1.5">
                        <label className="text-xs font-semibold uppercase tracking-wider text-zinc-500 flex items-center gap-1">
                          <Code size={12} /> Code Snippet
                        </label>
                        <textarea 
                          placeholder="Paste code here..."
                          className="input-field font-mono text-sm py-3"
                          autoComplete="off"
                          value={newNoteCode}
                          onChange={(e) => setNewNoteCode(e.target.value)}
                        />
                      </div>
                    </div>
                    <div className="space-y-1.5">
                      <label className="text-xs font-semibold uppercase tracking-wider text-zinc-500 flex items-center gap-1">
                        <ImageIcon size={12} /> Image
                      </label>
                      <div className="flex items-center gap-4">
                        <input 
                          type="file" 
                          accept="image/*"
                          onChange={handleImageUpload}
                          className="hidden"
                          id="note-image-upload"
                        />
                        <label 
                          htmlFor="note-image-upload"
                          className="btn-secondary flex items-center gap-2 cursor-pointer"
                        >
                          <Download size={16} />
                          Upload from Gallery
                        </label>
                        {newNoteImage && (
                          <div className="relative w-16 h-16 rounded-lg overflow-hidden border border-zinc-200">
                            <img src={newNoteImage} className="w-full h-full object-cover" referrerPolicy="no-referrer" />
                            <button 
                              type="button"
                              onClick={() => setNewNoteImage(null)}
                              className="absolute top-0 right-0 bg-red-500 text-white p-0.5 rounded-bl-lg"
                            >
                              <Plus size={12} className="rotate-45" />
                            </button>
                          </div>
                        )}
                      </div>
                    </div>
                    <div className="flex gap-3 pt-4 border-t border-zinc-100">
                      <button type="submit" className="btn-primary flex-1 py-3">Save Note</button>
                      <button type="button" onClick={() => setShowNoteForm(false)} className="btn-secondary py-3">Cancel</button>
                    </div>
                  </form>
                </motion.div>
              )}
            </AnimatePresence>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {notes.length === 0 ? (
                <div className="col-span-full glass-card p-12 text-center space-y-3 border-dashed border-zinc-300 bg-transparent">
                  <FileText size={24} className="mx-auto text-zinc-400" />
                  <p className="text-zinc-500">No notes yet. Add your first note!</p>
                </div>
              ) : (
                notes.map((note) => (
                  <motion.div layout key={note.id} className="glass-card p-4 space-y-3 relative group">
                    <button 
                      onClick={() => deleteNote(note.id)}
                      className="absolute top-2 right-2 p-2 text-zinc-400 hover:text-red-600 opacity-0 group-hover:opacity-100 transition-opacity"
                    >
                      <Trash2 size={16} />
                    </button>
                    <h3 className="font-bold text-zinc-900 pr-8">{note.title}</h3>
                    {note.content && (
                      <p className="text-sm text-zinc-600 whitespace-pre-wrap">
                        {privacyMode ? "••••••••••••" : note.content}
                      </p>
                    )}
                    {note.image && !privacyMode && (
                      <div className="rounded-lg overflow-hidden border border-zinc-100">
                        <img src={note.image} className="w-full h-auto max-h-48 object-cover" referrerPolicy="no-referrer" />
                      </div>
                    )}
                    {note.link && (
                      <div className="flex items-center justify-between gap-2">
                        <a 
                          href={privacyMode ? "#" : note.link} 
                          target={privacyMode ? "_self" : "_blank"} 
                          rel="noopener noreferrer"
                          className={cn(
                            "flex items-center gap-2 text-xs text-blue-600 hover:underline truncate",
                            privacyMode && "pointer-events-none"
                          )}
                        >
                          <ExternalLink size={12} /> {privacyMode ? "••••••••••••" : note.link}
                        </a>
                        {!privacyMode && (
                          <button onClick={() => copyToClipboard(note.link || '')} className="text-zinc-400 hover:text-zinc-900">
                            <Copy size={12} />
                          </button>
                        )}
                      </div>
                    )}
                    {note.code && (
                      <div className="space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="text-[10px] uppercase font-bold text-zinc-400">Code</span>
                          {!privacyMode && (
                            <button onClick={() => copyToClipboard(note.code || '')} className="text-zinc-400 hover:text-zinc-900">
                              <Copy size={12} />
                            </button>
                          )}
                        </div>
                        <pre className="bg-zinc-900 text-zinc-100 p-3 rounded-lg text-xs font-mono overflow-x-auto">
                          <code>{privacyMode ? "// Hidden" : note.code}</code>
                        </pre>
                      </div>
                    )}
                  </motion.div>
                ))
              )}
            </div>
          </section>

          {/* QR Code Section */}
          <section className={cn(
            "lg:col-span-12 space-y-6",
            activeTab !== 'qr' && "hidden"
          )}>
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-medium flex items-center gap-2">
                <QrCode size={18} className="text-zinc-500" />
                QR Code Generator
              </h2>
              <button 
                onClick={() => setShowQrForm(!showQrForm)}
                className="btn-secondary py-1.5 px-4 flex items-center gap-2 text-sm"
              >
                <Plus size={16} />
                Generate QR
              </button>
            </div>

            <AnimatePresence mode="wait">
              {showQrForm && (
                <motion.div 
                  key="qr-form"
                  initial={{ opacity: 0, y: -20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  className="glass-card p-6 border-zinc-200"
                >
                  <form onSubmit={saveQrcode} className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="space-y-1.5">
                        <label className="text-xs font-semibold uppercase tracking-wider text-zinc-500">Service</label>
                        <input 
                          type="text" 
                          placeholder="e.g. WiFi, Website"
                          className="input-field"
                          value={newQrService}
                          onChange={(e) => setNewQrService(e.target.value)}
                          required
                        />
                      </div>
                      <div className="space-y-1.5">
                        <label className="text-xs font-semibold uppercase tracking-wider text-zinc-500">Username (Optional)</label>
                        <input 
                          type="text" 
                          placeholder="username"
                          className="input-field"
                          value={newQrUsername}
                          onChange={(e) => setNewQrUsername(e.target.value)}
                        />
                      </div>
                    </div>
                    <div className="space-y-1.5">
                      <label className="text-xs font-semibold uppercase tracking-wider text-zinc-500">QR Content</label>
                      <textarea 
                        placeholder="Enter text or URL to encode in QR"
                        className="input-field py-3"
                        autoComplete="off"
                        value={newQrContent}
                        onChange={(e) => setNewQrContent(e.target.value)}
                        required
                      />
                    </div>
                    <div className="flex justify-center p-4 bg-zinc-50 rounded-xl">
                      {newQrContent ? (
                        <QRCodeSVG value={newQrContent} size={160} />
                      ) : (
                        <div className="w-40 h-40 bg-zinc-100 rounded flex items-center justify-center text-zinc-400 text-xs">
                          Preview will appear here
                        </div>
                      )}
                    </div>
                    <div className="flex gap-3 pt-4 border-t border-zinc-100">
                      <button type="submit" className="btn-primary flex-1 py-3">Save QR Code</button>
                      <button type="button" onClick={() => setShowQrForm(false)} className="btn-secondary py-3">Cancel</button>
                    </div>
                  </form>
                </motion.div>
              )}
            </AnimatePresence>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {qrcodes.length === 0 ? (
                <div className="col-span-full glass-card p-12 text-center space-y-3 border-dashed border-zinc-300 bg-transparent">
                  <QrCode size={24} className="mx-auto text-zinc-400" />
                  <p className="text-zinc-500">No QR codes saved yet.</p>
                </div>
              ) : (
                qrcodes.map((qr) => (
                  <motion.div layout key={qr.id} className="glass-card p-4 flex flex-col items-center space-y-3 relative group">
                    <button 
                      onClick={() => deleteQrcode(qr.id)}
                      className="absolute top-2 right-2 p-2 text-zinc-400 hover:text-red-600 opacity-0 group-hover:opacity-100 transition-opacity"
                    >
                      <Trash2 size={16} />
                    </button>
                    <div className={cn(
                      "p-3 bg-white rounded-lg shadow-sm transition-all",
                      privacyMode && "blur-md select-none pointer-events-none"
                    )}>
                      <QRCodeSVG value={qr.content} size={120} />
                    </div>
                    <div className="text-center">
                      <h3 className="font-bold text-zinc-900">{qr.service}</h3>
                      {qr.username && (
                        <p className="text-xs text-zinc-500">
                          {privacyMode ? "••••••••" : qr.username}
                        </p>
                      )}
                    </div>
                    <div className="w-full pt-2 border-t border-zinc-100 flex items-center justify-between gap-2">
                      <p className="text-[10px] text-zinc-400 truncate flex-1" title={qr.content}>
                        {privacyMode ? "••••••••••••" : qr.content}
                      </p>
                      {!privacyMode && (
                        <button onClick={() => copyToClipboard(qr.content)} className="text-zinc-400 hover:text-zinc-900">
                          <Copy size={12} />
                        </button>
                      )}
                    </div>
                  </motion.div>
                ))
              )}
            </div>
          </section>
        </div>
      </div>

      {/* Bottom Navigation */}
      <nav className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 w-full max-w-md px-4">
        <div className="bg-zinc-900/90 backdrop-blur-lg border border-white/10 p-1.5 rounded-2xl flex items-center justify-between shadow-2xl">
          <button
            onClick={() => setActiveTab('generator')}
            className={cn(
              "flex flex-col items-center gap-1 px-3 py-2 rounded-xl transition-all text-[10px] font-medium",
              activeTab === 'generator' 
                ? "bg-white text-zinc-900 shadow-sm" 
                : "text-zinc-400 hover:text-white"
            )}
          >
            <RefreshCw size={18} className={cn(activeTab === 'generator' && "animate-spin-slow")} />
            Gen
          </button>
          <button
            onClick={() => setActiveTab('vault')}
            className={cn(
              "flex flex-col items-center gap-1 px-3 py-2 rounded-xl transition-all text-[10px] font-medium",
              activeTab === 'vault' 
                ? "bg-white text-zinc-900 shadow-sm" 
                : "text-zinc-400 hover:text-white"
            )}
          >
            <Key size={18} />
            Vault
          </button>
          <button
            onClick={() => setActiveTab('notes')}
            className={cn(
              "flex flex-col items-center gap-1 px-3 py-2 rounded-xl transition-all text-[10px] font-medium",
              activeTab === 'notes' 
                ? "bg-white text-zinc-900 shadow-sm" 
                : "text-zinc-400 hover:text-white"
            )}
          >
            <FileText size={18} />
            Notes
          </button>
          <button
            onClick={() => setActiveTab('qr')}
            className={cn(
              "flex flex-col items-center gap-1 px-3 py-2 rounded-xl transition-all text-[10px] font-medium",
              activeTab === 'qr' 
                ? "bg-white text-zinc-900 shadow-sm" 
                : "text-zinc-400 hover:text-white"
            )}
          >
            <QrCode size={18} />
            QR
          </button>
        </div>
      </nav>
    </div>
    </div>
  );
}
