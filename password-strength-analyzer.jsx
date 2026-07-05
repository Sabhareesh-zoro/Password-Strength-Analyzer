import React, { useState, useEffect, useMemo } from 'react';
import {
  Eye, EyeOff, Check, X, Lock, ShieldX, CheckCircle2,
  RefreshCw, Copy, History, Trash2, Sparkles, AlertTriangle,
} from 'lucide-react';

/* ----------------------------------------------------------------------
 * Data
 * -------------------------------------------------------------------- */

// A sample of widely known breached/common passwords (used for demo
// purposes). Production systems should check against a real breach
// corpus, e.g. the Have I Been Pwned k-anonymity API.
const COMMON_PASSWORDS = new Set([
  '123456', '123456789', 'qwerty', 'password', '12345', '12345678', '111111',
  '1234567', 'sunshine', 'qwerty123', '1q2w3e4r', 'princess', '1234567890',
  '000000', 'abc123', '654321', 'dragon', 'master', 'monkey', 'letmein',
  'login', 'admin', 'welcome', 'solo', 'iloveyou', 'starwars', 'freedom',
  'whatever', 'qazwsx', 'trustno1', '666666', 'superman', 'batman',
  'football', 'baseball', 'hello', 'charlie', 'donald', 'michael',
  'jennifer', 'jordan', 'shadow', 'hunter', 'killer', 'cheese', 'andrew',
  'tigger', 'thomas', 'robert', 'daniel', 'harley', 'hockey', 'ranger',
  'buster', 'soccer', 'george', 'computer', 'michelle', 'jessica',
  'pepper', 'zaq1zaq1', '1q2w3e4r5t', 'password1', 'password123',
  'qwertyuiop', '1qaz2wsx', 'aa123456', 'iloveu', '123123', '121212',
  '1231234', '555555', '777777', '888888', '102030', '112233',
  'asdfghjkl', 'zxcvbnm', 'mynoob', 'changeme', 'letmein123',
  'welcome123', 'admin123', 'root', 'toor', 'guest', 'test', 'temp',
  'secret', 'ashley', 'nicole', 'amanda', 'chelsea', 'taylor', 'matthew',
  'andrea', 'joshua', 'samantha', 'victoria', 'martin', 'hannah',
  'william', 'alexis', 'brandon', 'samsung', 'iphone', 'google',
  'facebook', 'passw0rd', 'p@ssw0rd', 'letmein1', 'access', 'flower',
  'summer', 'winter', 'autumn', 'spring', 'abcd1234',
]);

// Simple word list for generating memorable passphrases.
const PASSPHRASE_WORDS = [
  'river', 'mountain', 'forest', 'garden', 'ocean', 'desert', 'canyon',
  'valley', 'meadow', 'harbor', 'bridge', 'castle', 'temple', 'island',
  'glacier', 'thunder', 'lantern', 'compass', 'anchor', 'falcon', 'eagle',
  'tiger', 'dolphin', 'panther', 'phoenix', 'wolf', 'otter', 'rabbit',
  'sparrow', 'maple', 'willow', 'cedar', 'birch', 'bamboo', 'lotus',
  'orchid', 'jasmine', 'coral', 'amber', 'copper', 'silver', 'crystal',
  'marble', 'granite', 'velvet', 'cotton', 'linen', 'autumn', 'winter',
  'summer', 'spring', 'sunrise', 'sunset', 'twilight', 'midnight',
  'morning', 'horizon', 'breeze', 'storm', 'cloud', 'rainbow', 'comet',
  'galaxy', 'planet', 'nebula', 'orbit', 'voyage', 'journey',
  'lighthouse', 'windmill', 'cabin', 'cottage', 'prairie', 'tundra',
  'savanna', 'jungle', 'lagoon', 'waterfall', 'plateau', 'summit',
  'boulder', 'pebble', 'ember', 'spark', 'ripple', 'whisper', 'echo',
];

const TIER_TEXT = {
  red: 'text-red-400',
  orange: 'text-orange-400',
  yellow: 'text-yellow-400',
  emerald: 'text-emerald-400',
  amber: 'text-amber-400',
};

const TIER_BG = {
  red: 'bg-red-500',
  orange: 'bg-orange-500',
  yellow: 'bg-yellow-500',
  emerald: 'bg-emerald-500',
  amber: 'bg-amber-500',
};

/* ----------------------------------------------------------------------
 * Pure helpers
 * -------------------------------------------------------------------- */

function secureRandomInt(max) {
  const arr = new Uint32Array(1);
  crypto.getRandomValues(arr);
  return arr[0] % max;
}

function calculateEntropy(pwd) {
  if (!pwd) return 0;
  let pool = 0;
  if (/[a-z]/.test(pwd)) pool += 26;
  if (/[A-Z]/.test(pwd)) pool += 26;
  if (/[0-9]/.test(pwd)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pwd)) pool += 33;
  if (pool === 0) return 0;
  return pwd.length * Math.log2(pool);
}

function hasSequentialChars(pwd) {
  const lower = pwd.toLowerCase();
  for (let i = 0; i < lower.length - 2; i++) {
    const a = lower.charCodeAt(i);
    const b = lower.charCodeAt(i + 1);
    const c = lower.charCodeAt(i + 2);
    if (b - a === 1 && c - b === 1) return true;
    if (a - b === 1 && b - c === 1) return true;
  }
  return false;
}

function hasRepeatedChars(pwd) {
  for (let i = 0; i < pwd.length - 2; i++) {
    if (pwd[i] === pwd[i + 1] && pwd[i + 1] === pwd[i + 2]) return true;
  }
  return false;
}

function hasKeyboardPattern(pwd) {
  const patterns = ['qwerty', 'asdfgh', 'zxcvbn', 'qazwsx', 'qwertyuiop', 'asdfghjkl', '1qaz2wsx', 'wsxedc'];
  const lower = pwd.toLowerCase();
  return patterns.some((p) => lower.includes(p) || lower.includes(p.split('').reverse().join('')));
}

function characterDiversity(pwd) {
  if (!pwd.length) return 1;
  return new Set(pwd).size / pwd.length;
}

async function sha256Hash(text) {
  const data = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function estimateCrackTime(entropyBits) {
  if (!entropyBits) return '—';
  const guessesPerSecond = 1e10; // fast offline attack assumption
  const avgGuesses = Math.pow(2, entropyBits - 1);
  const seconds = avgGuesses / guessesPerSecond;

  if (seconds < 1) return 'instantly';
  if (seconds < 60) return `${Math.round(seconds)} sec`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} hrs`;
  if (seconds < 31536000) return `${Math.round(seconds / 86400)} days`;
  const years = seconds / 31536000;
  if (years < 1000) return `${Math.round(years)} yrs`;
  if (years < 1e6) return `${Math.round(years / 1000)}k yrs`;
  if (years < 1e9) return `${Math.round(years / 1e6)}M yrs`;
  return `${(years / 1e9).toFixed(1)}B+ yrs`;
}

function generateStrongPassword(length) {
  const lower = 'abcdefghijkmnpqrstuvwxyz';
  const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const nums = '23456789';
  const special = '!@#$%^&*-_=+?';
  const all = lower + upper + nums + special;

  const chars = [
    lower[secureRandomInt(lower.length)],
    upper[secureRandomInt(upper.length)],
    nums[secureRandomInt(nums.length)],
    special[secureRandomInt(special.length)],
  ];

  for (let i = chars.length; i < length; i++) {
    chars.push(all[secureRandomInt(all.length)]);
  }

  for (let i = chars.length - 1; i > 0; i--) {
    const j = secureRandomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }

  return chars.join('');
}

function generatePassphrase() {
  const words = [0, 1, 2, 3].map(() => PASSPHRASE_WORDS[secureRandomInt(PASSPHRASE_WORDS.length)]);
  const capIndex = secureRandomInt(words.length);
  words[capIndex] = words[capIndex][0].toUpperCase() + words[capIndex].slice(1);
  const num = secureRandomInt(100);
  const separators = ['-', '.', '_'];
  const sep = separators[secureRandomInt(separators.length)];
  return words.join(sep) + sep + num;
}

function fallbackCopy(text) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand('copy'); } catch (e) { /* no-op */ }
  document.body.removeChild(ta);
}

function copyToClipboard(text, callback) {
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(callback).catch(() => { fallbackCopy(text); callback && callback(); });
  } else {
    fallbackCopy(text);
    callback && callback();
  }
}

/* ----------------------------------------------------------------------
 * Analysis
 * -------------------------------------------------------------------- */

function analyzePassword(pwd) {
  const checks = {
    length8: pwd.length >= 8,
    length12: pwd.length >= 12,
    hasLower: /[a-z]/.test(pwd),
    hasUpper: /[A-Z]/.test(pwd),
    hasNumber: /[0-9]/.test(pwd),
    hasSpecial: /[^a-zA-Z0-9]/.test(pwd),
    notCommon: pwd.length > 0 ? !COMMON_PASSWORDS.has(pwd.toLowerCase()) : true,
    noSequential: !hasSequentialChars(pwd),
    noRepeated: !hasRepeatedChars(pwd),
    noKeyboardPattern: !hasKeyboardPattern(pwd),
    goodDiversity: pwd.length === 0 ? true : characterDiversity(pwd) >= 0.6,
  };

  const entropy = calculateEntropy(pwd);
  let score = 0;

  if (pwd.length > 0) {
    const lengthPoints = Math.min(Math.max(pwd.length - 7, 0) * 4, 45);
    let varietyPoints = 0;
    if (checks.hasLower) varietyPoints += 5;
    if (checks.hasUpper) varietyPoints += 8;
    if (checks.hasNumber) varietyPoints += 8;
    if (checks.hasSpecial) varietyPoints += 10;
    const entropyBonus = Math.min(entropy / 4, 24);

    score = lengthPoints + varietyPoints + entropyBonus;

    if (!checks.noSequential) score -= 12;
    if (!checks.noRepeated) score -= 12;
    if (!checks.noKeyboardPattern) score -= 15;
    if (!checks.goodDiversity) score -= 10;

    score = Math.max(0, score);

    if (pwd.length < 6) score = Math.min(score, 20);
    else if (pwd.length < 8) score = Math.min(score, 40);

    if (!checks.notCommon) score = Math.min(score, 5);

    score = Math.round(Math.min(100, score));
  }

  let tier = null;
  let tierColor = null;
  if (pwd.length > 0) {
    if (score < 25) { tier = 'Very Weak'; tierColor = 'red'; }
    else if (score < 50) { tier = 'Weak'; tierColor = 'orange'; }
    else if (score < 70) { tier = 'Fair'; tierColor = 'yellow'; }
    else if (score < 90) { tier = 'Strong'; tierColor = 'emerald'; }
    else { tier = 'Very Strong'; tierColor = 'amber'; }
  }

  const suggestions = [];
  if (pwd.length > 0) {
    if (!checks.notCommon) suggestions.push('This is one of the most commonly breached passwords — avoid it completely.');
    if (!checks.length12) suggestions.push('Use at least 12 characters — 16 or more is even better.');
    if (!checks.hasUpper) suggestions.push('Add at least one uppercase letter.');
    if (!checks.hasLower) suggestions.push('Add at least one lowercase letter.');
    if (!checks.hasNumber) suggestions.push('Add at least one number.');
    if (!checks.hasSpecial) suggestions.push('Add a special character, like ! or # or -.');
    if (!checks.noKeyboardPattern) suggestions.push('Avoid keyboard patterns like "qwerty" or "asdf".');
    if (!checks.noSequential) suggestions.push('Avoid sequences like "abc" or "123".');
    if (!checks.noRepeated || !checks.goodDiversity) suggestions.push('Avoid repeating the same characters too often.');
  }

  return {
    checks,
    entropy,
    score,
    tier,
    tierColor,
    suggestions,
    crackTime: pwd.length > 0 ? estimateCrackTime(entropy) : '—',
  };
}

/* ----------------------------------------------------------------------
 * Small presentational components
 * -------------------------------------------------------------------- */

function ScoreDial({ score, tierColor, tier }) {
  const size = 128;
  const stroke = 9;
  const r = (size - stroke) / 2;
  const circumference = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, score));
  const offset = circumference * (1 - pct / 100);
  const colorClass = tierColor ? TIER_TEXT[tierColor] : 'text-stone-700';

  return (
    <div className="relative flex-shrink-0 w-32 h-32">
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="currentColor" strokeWidth={stroke} className="text-stone-800" />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke="currentColor"
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          className={`${colorClass} transition-all duration-500 ease-out`}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={`text-2xl font-bold tabular-nums ${colorClass}`}>{tier ? score : '—'}</span>
        <span className="text-xs uppercase tracking-wider text-stone-500 mt-0.5 text-center px-2 leading-tight">
          {tier || 'No input'}
        </span>
      </div>
    </div>
  );
}

function CheckItem({ passed, label }) {
  return (
    <div className={`flex items-center gap-2 text-sm ${passed ? 'text-stone-300' : 'text-stone-600'}`}>
      {passed ? <Check className="w-4 h-4 text-emerald-400 flex-shrink-0" /> : <X className="w-4 h-4 text-stone-700 flex-shrink-0" />}
      {label}
    </div>
  );
}

function GeneratedRow({ value, onGenerate, onCopy, onUse, copied, placeholder }) {
  return (
    <div>
      <div className="flex gap-2">
        <div className="flex-1 bg-stone-950 border border-stone-700 rounded-xl px-4 py-3 font-mono text-sm text-amber-300 truncate">
          {value || placeholder}
        </div>
        <button
          onClick={onGenerate}
          type="button"
          aria-label="Generate"
          className="px-3 rounded-xl bg-stone-800 hover:bg-stone-700 text-stone-300 transition focus:outline-none focus:ring-2 focus:ring-amber-500/50"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
        <button
          onClick={onCopy}
          disabled={!value}
          type="button"
          aria-label="Copy"
          className="px-3 rounded-xl bg-stone-800 hover:bg-stone-700 text-stone-300 transition disabled:opacity-40 focus:outline-none focus:ring-2 focus:ring-amber-500/50"
        >
          {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
        </button>
      </div>
      {value && (
        <button onClick={onUse} type="button" className="mt-2 text-xs text-amber-400 hover:text-amber-300 transition">
          Use this password ↑
        </button>
      )}
    </div>
  );
}

/* ----------------------------------------------------------------------
 * Main component
 * -------------------------------------------------------------------- */

export default function PasswordStrengthAnalyzer() {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [history, setHistory] = useState([]); // [{ hash, at }]
  const [isReused, setIsReused] = useState(false);
  const [checkingReuse, setCheckingReuse] = useState(false);
  const [saveMessage, setSaveMessage] = useState(null);
  const [confirmClear, setConfirmClear] = useState(false);
  const [genPassword, setGenPassword] = useState('');
  const [genPassphrase, setGenPassphrase] = useState('');
  const [genLength, setGenLength] = useState(16);
  const [copiedField, setCopiedField] = useState(null);

  const analysis = useMemo(() => analyzePassword(password), [password]);

  // Debounced reuse check against the simulated in-memory history.
  useEffect(() => {
    if (!password) {
      setIsReused(false);
      setCheckingReuse(false);
      return;
    }
    setCheckingReuse(true);
    const timer = setTimeout(async () => {
      const hash = await sha256Hash(password);
      setIsReused(history.some((h) => h.hash === hash));
      setCheckingReuse(false);
    }, 250);
    return () => clearTimeout(timer);
  }, [password, history]);

  useEffect(() => {
    if (!saveMessage) return;
    const t = setTimeout(() => setSaveMessage(null), 4000);
    return () => clearTimeout(t);
  }, [saveMessage]);

  const canSave = password.length > 0 && !isReused && analysis.checks.notCommon && analysis.score >= 50 && !checkingReuse;

  async function handleSave() {
    const hash = await sha256Hash(password);
    setHistory((prev) => [{ hash, at: Date.now() }, ...prev].slice(0, 5));
    setSaveMessage('Saved. This password is now checked against your next 5 password changes.');
    setPassword('');
  }

  function handleClear() {
    if (confirmClear) {
      setHistory([]);
      setConfirmClear(false);
    } else {
      setConfirmClear(true);
      setTimeout(() => setConfirmClear(false), 3000);
    }
  }

  function handleCopy(text, field) {
    copyToClipboard(text, () => {
      setCopiedField(field);
      setTimeout(() => setCopiedField(null), 1500);
    });
  }

  function handleUseGenerated(text) {
    setPassword(text);
    setShowPassword(true);
  }

  let saveHelperText = '';
  if (!canSave && password.length > 0 && !checkingReuse) {
    if (isReused) saveHelperText = 'Cannot save: this password was used recently.';
    else if (!analysis.checks.notCommon) saveHelperText = 'Cannot save: this is a commonly breached password.';
    else if (analysis.score < 50) saveHelperText = 'Cannot save: strength must reach at least "Fair".';
  }

  return (
    <div className="min-h-screen w-full bg-stone-950 p-4 sm:p-8">
      <div className="max-w-2xl mx-auto">
        {/* Header */}
        <div className="flex items-center gap-3 mb-6">
          <div className="p-2.5 rounded-xl bg-amber-500/10 border border-amber-500/20">
            <Lock className="w-5 h-5 text-amber-400" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-stone-100">Password Strength Analyzer</h1>
            <p className="text-sm text-stone-500">Test a password, get concrete fixes, and block reuse of recent ones.</p>
          </div>
        </div>

        {/* Input + score card */}
        <div className="bg-stone-900 border border-stone-800 rounded-2xl p-5 sm:p-6">
          <label htmlFor="pwd-input" className="text-xs font-semibold uppercase tracking-wider text-stone-500 mb-2 block">
            Enter a password to test
          </label>
          <div className="relative">
            <input
              id="pwd-input"
              type={showPassword ? 'text' : 'password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Type a password..."
              autoComplete="new-password"
              spellCheck={false}
              className="w-full bg-stone-950 border border-stone-700 rounded-xl px-4 py-3 pr-12 font-mono text-base text-stone-100 placeholder-stone-600 focus:outline-none focus:ring-2 focus:ring-amber-500/40 focus:border-amber-500/50 transition"
            />
            <button
              onClick={() => setShowPassword((s) => !s)}
              type="button"
              aria-label={showPassword ? 'Hide password' : 'Show password'}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-stone-500 hover:text-stone-300 transition focus:outline-none"
            >
              {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
            </button>
          </div>

          {password.length > 0 && (
            <div className="mt-5 flex items-center gap-5">
              <ScoreDial score={analysis.score} tierColor={analysis.tierColor} tier={analysis.tier} />
              <div className="flex-1 min-w-0">
                <div className="text-xs text-stone-500 mb-2 leading-relaxed">
                  Entropy <strong className="text-stone-300 font-mono">{Math.round(analysis.entropy)} bits</strong>
                  {' · '}Est. crack time <strong className="text-stone-300">{analysis.crackTime}</strong>
                </div>
                {checkingReuse ? (
                  <div className="flex items-center gap-1.5 text-xs text-stone-500">
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" /> Checking password history…
                  </div>
                ) : isReused ? (
                  <div className="flex items-center gap-1.5 text-xs text-red-400 font-medium">
                    <ShieldX className="w-3.5 h-3.5 flex-shrink-0" /> Matches a recently used password. Pick another.
                  </div>
                ) : history.length > 0 ? (
                  <div className="flex items-center gap-1.5 text-xs text-emerald-400">
                    <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0" /> Not found in recent password history.
                  </div>
                ) : (
                  <div className="text-xs text-stone-600">No password history saved yet.</div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Requirements checklist */}
        {password.length > 0 && (
          <div className="mt-4 bg-stone-900 border border-stone-800 rounded-2xl p-5 sm:p-6">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-stone-500 mb-3">Requirements</h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-2.5">
              <CheckItem passed={analysis.checks.length8} label="8+ characters" />
              <CheckItem passed={analysis.checks.length12} label="12+ characters (recommended)" />
              <CheckItem passed={analysis.checks.hasUpper} label="Uppercase letter" />
              <CheckItem passed={analysis.checks.hasLower} label="Lowercase letter" />
              <CheckItem passed={analysis.checks.hasNumber} label="Number" />
              <CheckItem passed={analysis.checks.hasSpecial} label="Special character" />
              <CheckItem passed={analysis.checks.notCommon} label="Not a common/breached password" />
              <CheckItem passed={analysis.checks.noKeyboardPattern} label="No keyboard patterns" />
              <CheckItem passed={analysis.checks.noSequential} label="No sequences (abc, 123)" />
              <CheckItem passed={analysis.checks.noRepeated && analysis.checks.goodDiversity} label="Avoids repetition" />
            </div>
          </div>
        )}

        {/* Suggestions */}
        {password.length > 0 && analysis.suggestions.length > 0 && (
          <div className="mt-4 bg-orange-500/5 border border-orange-500/20 rounded-2xl p-5 sm:p-6">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-orange-300/90 mb-2.5 flex items-center gap-2">
              <AlertTriangle className="w-3.5 h-3.5" /> Suggestions
            </h2>
            <ul className="space-y-1.5">
              {analysis.suggestions.map((s, i) => (
                <li key={i} className="text-sm text-stone-300 flex items-start gap-2">
                  <span className="text-orange-400 mt-0.5">•</span> {s}
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Save */}
        {password.length > 0 && (
          <div className="mt-4">
            <button
              onClick={handleSave}
              disabled={!canSave}
              type="button"
              className={`w-full py-3 rounded-xl font-semibold transition focus:outline-none focus:ring-2 focus:ring-amber-500/50 ${
                canSave ? 'bg-amber-500 hover:bg-amber-400 text-stone-950' : 'bg-stone-800 text-stone-600 cursor-not-allowed'
              }`}
            >
              Set as Current Password
            </button>
            {saveHelperText && <p className="text-xs text-stone-500 mt-2">{saveHelperText}</p>}
            {saveMessage && (
              <div className="mt-3 text-sm text-emerald-300 bg-emerald-500/10 border border-emerald-500/20 rounded-xl px-4 py-2.5 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 flex-shrink-0" /> {saveMessage}
              </div>
            )}
          </div>
        )}

        {/* Generator */}
        <div className="mt-8 bg-stone-900 border border-stone-800 rounded-2xl p-5 sm:p-6">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-stone-500 mb-1 flex items-center gap-2">
            <Sparkles className="w-3.5 h-3.5 text-amber-400" /> Generate a Stronger Alternative
          </h2>
          <p className="text-xs text-stone-600 mb-4">Generated locally in your browser. Nothing here is stored or sent anywhere.</p>

          <div className="mb-5">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-medium text-stone-400">Random password ({genLength} characters)</span>
              <div className="flex gap-1">
                {[12, 16, 20].map((len) => (
                  <button
                    key={len}
                    onClick={() => setGenLength(len)}
                    type="button"
                    className={`text-xs px-2 py-1 rounded-md transition ${
                      genLength === len ? 'bg-amber-500 text-stone-950 font-semibold' : 'bg-stone-800 text-stone-400 hover:bg-stone-700'
                    }`}
                  >
                    {len}
                  </button>
                ))}
              </div>
            </div>
            <GeneratedRow
              value={genPassword}
              placeholder="Click generate…"
              onGenerate={() => setGenPassword(generateStrongPassword(genLength))}
              onCopy={() => handleCopy(genPassword, 'pwd')}
              onUse={() => handleUseGenerated(genPassword)}
              copied={copiedField === 'pwd'}
            />
          </div>

          <div>
            <span className="text-xs font-medium text-stone-400 mb-2 block">Memorable passphrase</span>
            <GeneratedRow
              value={genPassphrase}
              placeholder="Click generate…"
              onGenerate={() => setGenPassphrase(generatePassphrase())}
              onCopy={() => handleCopy(genPassphrase, 'phrase')}
              onUse={() => handleUseGenerated(genPassphrase)}
              copied={copiedField === 'phrase'}
            />
          </div>
        </div>

        {/* History */}
        <div className="mt-4 bg-stone-900 border border-stone-800 rounded-2xl p-5 sm:p-6">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-stone-500 flex items-center gap-2">
              <History className="w-3.5 h-3.5" /> Password History ({history.length}/5)
            </h2>
            {history.length > 0 && (
              <button
                onClick={handleClear}
                type="button"
                className={`text-xs flex items-center gap-1 transition ${confirmClear ? 'text-red-400' : 'text-stone-500 hover:text-stone-300'}`}
              >
                <Trash2 className="w-3.5 h-3.5" /> {confirmClear ? 'Confirm clear?' : 'Clear'}
              </button>
            )}
          </div>
          {history.length === 0 ? (
            <p className="text-xs text-stone-600">No saved passwords yet. Use "Set as Current Password" above to add one.</p>
          ) : (
            <ul className="space-y-2">
              {history.map((h) => (
                <li key={h.at} className="flex items-center justify-between text-xs bg-stone-950 border border-stone-800 rounded-lg px-3 py-2">
                  <span className="font-mono text-stone-500">{h.hash.slice(0, 20)}…</span>
                  <span className="text-stone-600">{new Date(h.at).toLocaleTimeString()}</span>
                </li>
              ))}
            </ul>
          )}
        </div>

        {/* Footer note */}
        <p className="mt-6 text-xs text-stone-600 leading-relaxed border-t border-stone-800 pt-4">
          <strong className="text-stone-500">About this demo:</strong> password history is simulated in-browser with
          SHA-256 hashes held in memory only — nothing leaves your browser, and it resets on refresh. A real system
          must never rely on this alone: it needs a server-side check against a database using a slow, salted hash
          (bcrypt, scrypt, or Argon2), not a fast hash like SHA-256.
        </p>
      </div>
    </div>
  );
}
