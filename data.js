const SCHEMES = [
  {
    id: "kzg",
    name: "KZG",
    fullName: "Kate–Zaverucha–Goldberg commitments",
    family: "Pairing-based polynomial commitments",
    commitment: "1 group element",
    openingProof: "O(1)",
    setup: "Structured SRS, trusted setup",
    cryptoBase: "Pairings, скрытая точка τ, q-SDH/q-PKE-подобные предположения в зависимости от формализации",
    prover: "MSM по SRS, quotient polynomial, opening commitment",
    verifier: "Константное число pairing-проверок",
    batching: "Сильный батчинг через случайные линейные комбинации и quotient polynomial",
    recursion: "Хуже для глубокой рекурсии: pairing-проверку дорого арифметизовать",
    thesisComment:
      "Выигрывает, когда главные критерии — минимальный размер открытия и короткая внешняя проверка. Цена — trusted setup и pairings.",
    badge: "compact proof"
  },
  {
    id: "ipa",
    name: "IPA",
    fullName: "Inner-product-argument commitments",
    family: "Pairing-free commitments",
    commitment: "1 group element",
    openingProof: "O(log n)",
    setup: "Публичные генераторы, без toxic waste",
    cryptoBase: "Сложность дискретного логарифма и неизвестность линейных соотношений между генераторами",
    prover: "MSM, раунды inner product argument, Fiat–Shamir transcript",
    verifier: "Групповые операции, MSM или multiexponentiation",
    batching: "Линейная агрегация возможна, но proof остается логарифмическим",
    recursion: "Обычно удобнее KZG: нет pairings, verifier состоит из curve operations",
    thesisComment:
      "Подходит, когда важны отсутствие toxic waste, pairing-free verifier и рекурсивная композиция.",
    badge: "recursion friendly"
  },
  {
    id: "fri",
    name: "FRI",
    fullName: "Fast Reed–Solomon IOPP-based commitments",
    family: "Transparent STARK-like approach",
    commitment: "Merkle root",
    openingProof: "O(q log n)",
    setup: "Прозрачные публичные параметры",
    cryptoBase: "Collision resistance хэш-функции и soundness low-degree testing",
    prover: "Low-degree extension, Merkle trees, FRI folding",
    verifier: "Merkle paths, hash checks, локальные field checks",
    batching: "Батчинг через composition polynomial, общие oracle-запросы и shared Merkle openings",
    recursion: "Возможна, но чувствительна к выбору hash function и числу queries",
    thesisComment:
      "Подходит для прозрачных STARK-like систем. Proof крупнее, зато нет SRS и pairings.",
    badge: "transparent"
  }
];

const MODEL_CONSTANTS = {
  kzgGroupBytes: 48,
  ipaGroupBytes: 32,
  fieldBytes: 32,
  scalarBytes: 32,
  hashBytes: 32,
  pairingExternalCost: 720,
  pairingCircuitCost: 12000,
  curveCircuitCost: 520,
  hashCircuitCost: 95,
  hashUnit: 0.35,
  fieldUnit: 0.08
};
