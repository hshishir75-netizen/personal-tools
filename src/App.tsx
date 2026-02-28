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
  Edit2,
  FileText,
  QrCode,
  Link as LinkIcon,
  Code,
  Image as ImageIcon,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Download
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

export default function App() {
  const [activeTab, setActiveTab] = useState<'generator' | 'vault' | 'notes' | 'qr'>('generator');
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
    fetchPasswords();
    fetchNotes();
    fetchQrcodes();
  }, [generatePassword]);

  const fetchPasswords = async () => {
    try {
      const res = await fetch('/api/passwords');
      const data = await res.json();
      setSavedPasswords(data);
    } catch (err) {
      console.error("Failed to fetch passwords", err);
    }
  };

  const savePassword = async (e: FormEvent) => {
    e.preventDefault();
    if (!newService || !newPassword) return;

    try {
      const url = editingId ? `/api/passwords/${editingId}` : '/api/passwords';
      const method = editingId ? 'PUT' : 'POST';

      const res = await fetch(url, {
        method: method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          service: newService,
          username: newUsername,
          email: newEmail,
          phone: newPhone,
          backup_code: newBackupCode,
          password: newPassword,
          custom_fields: customFields
        })
      });
      if (res.ok) {
        resetForm();
        fetchPasswords();
      }
    } catch (err) {
      console.error("Failed to save password", err);
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

  const startEdit = (item: SavedPassword) => {
    setNewService(item.service);
    setNewUsername(item.username || '');
    setNewEmail(item.email || '');
    setNewPhone(item.phone || '');
    setNewBackupCode(item.backup_code || '');
    setNewPassword(item.password);
    setCustomFields(item.custom_fields || []);
    setEditingId(item.id);
    setShowForm(true);
    // Scroll to form or ensure it's visible
    window.scrollTo({ top: 0, behavior: 'smooth' });
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
      console.error("Failed to delete password", err);
    }
  };

  const fetchNotes = async () => {
    try {
      const res = await fetch('/api/notes');
      const data = await res.json();
      setNotes(data);
    } catch (err) {
      console.error("Failed to fetch notes", err);
    }
  };

  const saveNote = async (e: FormEvent) => {
    e.preventDefault();
    
    const titleToSave = newNoteTitle.trim() || `title ${notes.length + 1}`;

    try {
      const res = await fetch('/api/notes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: titleToSave,
          content: newNoteContent,
          image: newNoteImage,
          link: newNoteLink,
          code: newNoteCode
        })
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
      console.error("Failed to save note", err);
    }
  };

  const deleteNote = async (id: number) => {
    try {
      await fetch(`/api/notes/${id}`, { method: 'DELETE' });
      fetchNotes();
    } catch (err) {
      console.error("Failed to delete note", err);
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

  const fetchQrcodes = async () => {
    try {
      const res = await fetch('/api/qrcodes');
      const data = await res.json();
      setQrcodes(data);
    } catch (err) {
      console.error("Failed to fetch QR codes", err);
    }
  };

  const saveQrcode = async (e: FormEvent) => {
    e.preventDefault();
    if (!newQrService || !newQrContent) return;

    try {
      const res = await fetch('/api/qrcodes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          service: newQrService,
          username: newQrUsername,
          content: newQrContent
        })
      });
      if (res.ok) {
        setNewQrService('');
        setNewQrUsername('');
        setNewQrContent('');
        setShowQrForm(false);
        fetchQrcodes();
      }
    } catch (err) {
      console.error("Failed to save QR code", err);
    }
  };

  const deleteQrcode = async (id: number) => {
    try {
      await fetch(`/api/qrcodes/${id}`, { method: 'DELETE' });
      fetchQrcodes();
    } catch (err) {
      console.error("Failed to delete QR code", err);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const togglePassVisibility = (id: number) => {
    setShowPassMap(prev => ({ ...prev, [id]: !prev[id] }));
  };

  return (
    <div className="min-h-screen bg-[#f8f9fa] p-4 md:p-8 pb-24 md:pb-8">
      <div className="max-w-4xl mx-auto space-y-8">
        {/* Header */}
        <header className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-zinc-900 rounded-xl flex items-center justify-center text-white">
              <Shield size={24} />
            </div>
            <div>
              <h1 className="text-2xl font-semibold tracking-tight">CipherVault</h1>
              <p className="text-sm text-zinc-500">Secure your digital identity</p>
            </div>
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

            <AnimatePresence>
              {showForm && (
                <motion.div 
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
                          <p className="text-xs text-zinc-500">{item.username || item.email || 'No identifier'}</p>
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
                          onClick={() => copyToClipboard(item.password)}
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

                    <AnimatePresence>
                      {expandedId === item.id && (
                        <motion.div 
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
                                  <p className="text-sm font-medium">{item.username}</p>
                                </div>
                              )}
                              {item.email && (
                                <div className="space-y-1">
                                  <span className="text-[10px] uppercase font-bold text-zinc-400">Email</span>
                                  <p className="text-sm font-medium">{item.email}</p>
                                </div>
                              )}
                              {item.phone && (
                                <div className="space-y-1">
                                  <span className="text-[10px] uppercase font-bold text-zinc-400">Phone</span>
                                  <p className="text-sm font-medium">{item.phone}</p>
                                </div>
                              )}
                              {item.backup_code && (
                                <div className="space-y-1">
                                  <span className="text-[10px] uppercase font-bold text-zinc-400">Backup Code</span>
                                  <p className="text-sm font-medium">{item.backup_code}</p>
                                </div>
                              )}
                            </div>
                            
                            <div className="space-y-1">
                              <span className="text-[10px] uppercase font-bold text-zinc-400">Password</span>
                              <div className="flex items-center gap-2">
                                <p className="text-sm font-mono font-medium">
                                  {showPassMap[item.id] ? item.password : '••••••••••••'}
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
                                    <p className="text-sm font-medium">{field.value}</p>
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

            <AnimatePresence>
              {showNoteForm && (
                <motion.div 
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
                    {note.content && <p className="text-sm text-zinc-600 whitespace-pre-wrap">{note.content}</p>}
                    {note.image && (
                      <div className="rounded-lg overflow-hidden border border-zinc-100">
                        <img src={note.image} className="w-full h-auto max-h-48 object-cover" referrerPolicy="no-referrer" />
                      </div>
                    )}
                    {note.link && (
                      <a 
                        href={note.link} 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="flex items-center gap-2 text-xs text-blue-600 hover:underline"
                      >
                        <ExternalLink size={12} /> {note.link}
                      </a>
                    )}
                    {note.code && (
                      <pre className="bg-zinc-900 text-zinc-100 p-3 rounded-lg text-xs font-mono overflow-x-auto">
                        <code>{note.code}</code>
                      </pre>
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

            <AnimatePresence>
              {showQrForm && (
                <motion.div 
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
                    <div className="p-3 bg-white rounded-lg shadow-sm">
                      <QRCodeSVG value={qr.content} size={120} />
                    </div>
                    <div className="text-center">
                      <h3 className="font-bold text-zinc-900">{qr.service}</h3>
                      {qr.username && <p className="text-xs text-zinc-500">{qr.username}</p>}
                    </div>
                    <div className="w-full pt-2 border-t border-zinc-100">
                      <p className="text-[10px] text-zinc-400 truncate text-center" title={qr.content}>
                        {qr.content}
                      </p>
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
  );
}
