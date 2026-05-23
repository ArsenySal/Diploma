const SCHEMES = [
  {
    id: "kzg",
    name: "KZG",
    commitment: "1 group element",
    openingProof: "O(1)",
    setup: "Structured SRS, trusted setup"
  },
  {
    id: "ipa",
    name: "IPA",
    commitment: "1 group element",
    openingProof: "O(log n)",
    setup: "Публичные генераторы, без toxic waste"
  },
  {
    id: "fri",
    name: "FRI",
    commitment: "Merkle root",
    openingProof: "O(q log n)",
    setup: "Прозрачные публичные параметры"
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
