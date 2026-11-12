import { KEMS } from './crypto.mjs';

export const algorithms = Object.keys(KEMS);
export const defaultPolicy = Object.freeze({
  allowed: Object.freeze([...algorithms]),
  minimumLevel: 3,
  experimental: false,
  preferred: 'standard',
});

export function validatePolicy(policy) {
  if (!policy || typeof policy !== 'object' || Object.keys(policy).length !== 4 ||
      !Array.isArray(policy.allowed) || policy.allowed.length > algorithms.length ||
      new Set(policy.allowed).size !== policy.allowed.length ||
      !policy.allowed.every(name => algorithms.includes(name)) ||
      ![3, 5].includes(policy.minimumLevel) || typeof policy.experimental !== 'boolean' ||
      !['standard', ...algorithms].includes(policy.preferred)) {
    throw new Error('Invalid key exchange policy');
  }
  return policy;
}

function exclusion(policy, algorithm) {
  if (!policy.allowed.includes(algorithm)) return 'Excluded by allowlist';
  if (KEMS[algorithm].level < policy.minimumLevel) return 'Below minimum level';
  if (KEMS[algorithm].experimental && !policy.experimental) return 'Experimental opt-in required';
  return '';
}

export function eligibleAlgorithms(policy) {
  return algorithms.filter(name => !exclusion(policy, name));
}

export function selectKeyExchange(initiator, responder) {
  validatePolicy(initiator);
  validatePolicy(responder);
  const candidates = algorithms.map(name => ({
    name,
    initiator: exclusion(initiator, name),
    responder: exclusion(responder, name),
    votes: Number(initiator.preferred === name) + Number(responder.preferred === name),
  }));
  // Catalog order prefers the standard algorithm when both candidates have equal votes.
  const selected = candidates.filter(candidate => !candidate.initiator && !candidate.responder)
    .sort((a, b) => b.votes - a.votes)[0]?.name ?? null;
  return { initiator, responder, candidates, selected };
}
