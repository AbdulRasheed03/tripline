// Shared lab data for the live server, the attack simulator and the browser demo.
// These passwords are public on purpose: this is a training target, not a real system.

// "admin" uses a password from every common wordlist, so a brute force wins when auto-block is off.
// "farid" falls to the second round of a password spray. The others are strong.
export const ACCOUNTS = {
  admin: 'sunshine',
  aina: 'Kopi-Rawang-88!',
  farid: 'Welcome@2026',
  mei: 'tr0ub4dor&3-horse',
  raj: 'Raj#Payroll#7731',
  siti: 'S1ti!Library-Card',
};

// Top of the usual leaked-password lists. "sunshine" is number 16.
export const WORDLIST = ['123456', 'password', '123456789', 'qwerty', '12345678', '111111', '1234567', 'iloveyou', 'admin', 'welcome', 'monkey', 'dragon', 'letmein', 'football', 'abc123', 'sunshine', 'princess', 'password1', 'master', 'shadow'];

export const SPRAY_USERS = ['admin', 'aina', 'farid', 'mei', 'raj', 'siti', 'hr', 'finance', 'it.support', 'test'];
export const SPRAY_PASSWORDS = ['Password1', 'Welcome@2026', 'Winter2026!'];

export const INJECTIONS = [
  ["admin' OR '1'='1' -- ", 'x'],
  ['admin', "' or 1=1#"],
  ["admin' UNION SELECT username, password FROM users--", 'x'],
  ['<script>alert(document.cookie)</script>', 'x'],
];
