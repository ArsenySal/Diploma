const formElements = {
  degreePower: document.getElementById("degree-power"),
  polynomialCount: document.getElementById("polynomial-count"),
  openingPoints: document.getElementById("opening-points"),
  friQueries: document.getElementById("fri-queries"),
  blowupFactor: document.getElementById("blowup-factor"),
  priority: document.getElementById("priority"),
  trustedSetupAllowed: document.getElementById("trusted-setup-allowed"),
  recursionRequired: document.getElementById("recursion-required"),
  transparencyRequired: document.getElementById("transparency-required")
};

const schemeCardsContainer = document.getElementById("scheme-cards");
const estimatesTableBody = document.querySelector("#estimates-table tbody");
const recommendedSchemeElement = document.getElementById("recommended-scheme");
const recommendationTextElement = document.getElementById("recommendation-text");
const scoreBarsContainer = document.getElementById("score-bars");

function readParams() {
  const degreePower = Number(formElements.degreePower.value);
  const polynomialCount = clamp(Number(formElements.polynomialCount.value), 1, 64);
  const openingPoints = clamp(Number(formElements.openingPoints.value), 1, 32);
  const friQueries = clamp(Number(formElements.friQueries.value), 4, 128);
  const blowupFactor = Number(formElements.blowupFactor.value);

  formElements.polynomialCount.value = polynomialCount;
  formElements.openingPoints.value = openingPoints;
  formElements.friQueries.value = friQueries;

  return {
    degreePower,
    n: 2 ** degreePower,
    logN: degreePower,
    polynomialCount,
    openingPoints,
    friQueries,
    blowupFactor,
    priority: formElements.priority.value,
    trustedSetupAllowed: formElements.trustedSetupAllowed.checked,
    recursionRequired: formElements.recursionRequired.checked,
    transparencyRequired: formElements.transparencyRequired.checked
  };
}

function clamp(value, min, max) {
  if (Number.isNaN(value)) return min;
  return Math.max(min, Math.min(max, value));
}

function calculateEstimates(params) {
  const c = MODEL_CONSTANTS;
  const openedValues = params.polynomialCount * params.openingPoints;
  const friLayers = Math.ceil(Math.log2(params.blowupFactor)) + Math.max(1, params.logN - 2);

  const kzgProofBytes =
    c.kzgGroupBytes +
    openedValues * c.fieldBytes +
    2 * c.scalarBytes;

  const ipaProofBytes =
    (2 * params.logN + 2) * c.ipaGroupBytes +
    (params.logN + openedValues + 1) * c.scalarBytes;

  const friProofBytes =
    params.friQueries * params.logN * 2 * c.hashBytes +
    params.friQueries * friLayers * 2 * c.fieldBytes +
    params.friQueries * c.hashBytes;

  const kzgProver =
    params.polynomialCount * params.n * 1.4 +
    openedValues * params.n * 0.18;

  const ipaProver =
    params.polynomialCount * params.n * 1.15 +
    params.polynomialCount * params.logN * 340 +
    openedValues * params.logN * 120;

  const friProver =
    params.polynomialCount * params.n * params.blowupFactor * 0.55 +
    params.polynomialCount * params.n * params.logN * 0.12 +
    params.polynomialCount * params.n * params.blowupFactor * c.hashUnit;

  const kzgVerifier =
    2 * c.pairingCost +
    openedValues * 18 +
    params.polynomialCount * 6;

  const ipaVerifier =
    params.logN * 95 +
    openedValues * 28 +
    params.polynomialCount * 18;

  const friVerifier =
    params.friQueries * params.logN * 2 * c.hashUnit * 100 +
    params.friQueries * friLayers * c.fieldUnit * 100 +
    openedValues * 12;

  return {
    kzg: {
      proofBytes: Math.round(kzgProofBytes),
      proverCost: Math.round(kzgProver),
      verifierCost: Math.round(kzgVerifier),
      commitmentBytes: params.polynomialCount * c.kzgGroupBytes
    },
    ipa: {
      proofBytes: Math.round(ipaProofBytes),
      proverCost: Math.round(ipaProver),
      verifierCost: Math.round(ipaVerifier),
      commitmentBytes: params.polynomialCount * c.ipaGroupBytes
    },
    fri: {
      proofBytes: Math.round(friProofBytes),
      proverCost: Math.round(friProver),
      verifierCost: Math.round(friVerifier),
      commitmentBytes: params.polynomialCount * c.hashBytes
    }
  };
}

function normalizeCost(value, allValues) {
  const min = Math.min(...allValues);
  const max = Math.max(...allValues);
  if (max === min) return 100;
  return 100 - ((value - min) / (max - min)) * 70;
}

function scoreSchemes(params, estimates) {
  const proofValues = SCHEMES.map((scheme) => estimates[scheme.id].proofBytes);
  const proverValues = SCHEMES.map((scheme) => estimates[scheme.id].proverCost);
  const verifierValues = SCHEMES.map((scheme) => estimates[scheme.id].verifierCost);

  const base = {
    kzg: {
      proofSize: normalizeCost(estimates.kzg.proofBytes, proofValues),
      proverCost: normalizeCost(estimates.kzg.proverCost, proverValues),
      verifierCost: normalizeCost(estimates.kzg.verifierCost, verifierValues),
      noTrustedSetup: 25,
      recursion: 42,
      transparency: 20,
      batching: 95
    },
    ipa: {
      proofSize: normalizeCost(estimates.ipa.proofBytes, proofValues),
      proverCost: normalizeCost(estimates.ipa.proverCost, proverValues),
      verifierCost: normalizeCost(estimates.ipa.verifierCost, verifierValues),
      noTrustedSetup: 82,
      recursion: 88,
      transparency: 62,
      batching: 75
    },
    fri: {
      proofSize: normalizeCost(estimates.fri.proofBytes, proofValues),
      proverCost: normalizeCost(estimates.fri.proverCost, proverValues),
      verifierCost: normalizeCost(estimates.fri.verifierCost, verifierValues),
      noTrustedSetup: 98,
      recursion: 64,
      transparency: 98,
      batching: 68
    }
  };

  const weights = getWeights(params);
  const result = {};

  for (const scheme of SCHEMES) {
    const s = base[scheme.id];

    let total =
      s.proofSize * weights.proofSize +
      s.proverCost * weights.proverCost +
      s.verifierCost * weights.verifierCost +
      s.noTrustedSetup * weights.noTrustedSetup +
      s.recursion * weights.recursion +
      s.transparency * weights.transparency +
      s.batching * weights.batching;

    if (!params.trustedSetupAllowed && scheme.id === "kzg") {
      total -= 35;
    }

    if (params.recursionRequired && scheme.id === "kzg") {
      total -= 18;
    }

    if (params.transparencyRequired && scheme.id !== "fri") {
      total -= scheme.id === "kzg" ? 45 : 18;
    }

    result[scheme.id] = {
      score: Math.max(0, Math.min(100, Math.round(total))),
      components: s
    };
  }

  return result;
}

function getWeights(params) {
  const presets = {
    balanced: {
      proofSize: 0.2,
      proverCost: 0.15,
      verifierCost: 0.17,
      noTrustedSetup: 0.15,
      recursion: 0.15,
      transparency: 0.1,
      batching: 0.08
    },
    proofSize: {
      proofSize: 0.48,
      proverCost: 0.07,
      verifierCost: 0.18,
      noTrustedSetup: 0.06,
      recursion: 0.07,
      transparency: 0.04,
      batching: 0.1
    },
    verifierCost: {
      proofSize: 0.15,
      proverCost: 0.08,
      verifierCost: 0.45,
      noTrustedSetup: 0.08,
      recursion: 0.12,
      transparency: 0.04,
      batching: 0.08
    },
    proverCost: {
      proofSize: 0.12,
      proverCost: 0.45,
      verifierCost: 0.12,
      noTrustedSetup: 0.08,
      recursion: 0.08,
      transparency: 0.07,
      batching: 0.08
    },
    noTrustedSetup: {
      proofSize: 0.1,
      proverCost: 0.08,
      verifierCost: 0.1,
      noTrustedSetup: 0.46,
      recursion: 0.1,
      transparency: 0.1,
      batching: 0.06
    },
    recursion: {
      proofSize: 0.1,
      proverCost: 0.08,
      verifierCost: 0.16,
      noTrustedSetup: 0.12,
      recursion: 0.42,
      transparency: 0.06,
      batching: 0.06
    },
    transparency: {
      proofSize: 0.08,
      proverCost: 0.08,
      verifierCost: 0.1,
      noTrustedSetup: 0.2,
      recursion: 0.08,
      transparency: 0.42,
      batching: 0.04
    }
  };

  return presets[params.priority] ?? presets.balanced;
}

function renderSchemeCards(estimates) {
  schemeCardsContainer.innerHTML = "";

  for (const scheme of SCHEMES) {
    const estimate = estimates[scheme.id];

    const card = document.createElement("article");
    card.className = "scheme-card";
    card.innerHTML = `
      <div class="scheme-card-header">
        <div class="scheme-title">
          <h3>${scheme.name}</h3>
          <p>${scheme.family}</p>
        </div>
        <span class="badge">${scheme.badge}</span>
      </div>

      <ul class="metric-list">
        <li class="metric"><span>Криптографическая основа</span><span>${scheme.cryptoBase}</span></li>
        <li class="metric"><span>Commitment</span><span>${scheme.commitment}</span></li>
        <li class="metric"><span>Opening proof</span><span>${scheme.openingProof}</span></li>
        <li class="metric"><span>Setup</span><span>${scheme.setup}</span></li>
        <li class="metric"><span>Proof size, усл. байты</span><span>${formatNumber(estimate.proofBytes)}</span></li>
      </ul>

      <p class="scheme-comment">${scheme.thesisComment}</p>
    `;

    schemeCardsContainer.appendChild(card);
  }
}

function renderTable(estimates) {
  estimatesTableBody.innerHTML = "";

  for (const scheme of SCHEMES) {
    const estimate = estimates[scheme.id];

    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${scheme.name}</td>
      <td>${scheme.commitment}<br><small>${formatNumber(estimate.commitmentBytes)} усл. байт</small></td>
      <td>${scheme.openingProof}</td>
      <td>${formatNumber(estimate.proofBytes)}</td>
      <td>${formatNumber(estimate.proverCost)}</td>
      <td>${formatNumber(estimate.verifierCost)}</td>
      <td>${scheme.setup}</td>
      <td>${scheme.recursion}</td>
    `;

    estimatesTableBody.appendChild(row);
  }
}

function renderRecommendation(scores, params) {
  const ranked = SCHEMES
    .map((scheme) => ({
      ...scheme,
      score: scores[scheme.id].score
    }))
    .sort((a, b) => b.score - a.score);

  const best = ranked[0];
  recommendedSchemeElement.textContent = best.name;
  recommendationTextElement.textContent = buildRecommendationText(best.id, params);
}

function buildRecommendationText(schemeId, params) {
  if (schemeId === "kzg") {
    return "KZG выбран потому, что в заданном сценарии сильнее всего ценятся компактное открытие, эффективный батчинг и короткая внешняя проверка. Ограничение: схема опирается на structured SRS и pairing-проверки.";
  }

  if (schemeId === "ipa") {
    return "IPA выбран потому, что сценарий лучше согласуется с pairing-free verifier, отсутствием toxic waste и рекурсивной проверкой. Ограничение: opening proof растет как O(log n).";
  }

  if (schemeId === "fri") {
    return "FRI выбран потому, что в сценарии важны прозрачность, отсутствие SRS и STARK-like модель. Ограничение: proof крупнее из-за Merkle paths, FRI-слоев и query complexity.";
  }

  return "Рекомендация не определена.";
}

function renderScoreBars(scores) {
  scoreBarsContainer.innerHTML = "";

  const ranked = SCHEMES
    .map((scheme) => ({
      name: scheme.name,
      score: scores[scheme.id].score
    }))
    .sort((a, b) => b.score - a.score);

  for (const item of ranked) {
    const wrapper = document.createElement("div");
    wrapper.className = "score-item";
    wrapper.innerHTML = `
      <div class="score-head">
        <span>${item.name}</span>
        <span>${item.score}/100</span>
      </div>
      <div class="score-track">
        <div class="score-fill" style="width: ${item.score}%"></div>
      </div>
    `;
    scoreBarsContainer.appendChild(wrapper);
  }
}

function formatNumber(value) {
  return new Intl.NumberFormat("ru-RU").format(value);
}

function update() {
  const params = readParams();
  const estimates = calculateEstimates(params);
  const scores = scoreSchemes(params, estimates);

  renderSchemeCards(estimates);
  renderTable(estimates);
  renderRecommendation(scores, params);
  renderScoreBars(scores);
}

for (const element of Object.values(formElements)) {
  element.addEventListener("input", update);
  element.addEventListener("change", update);
}

update();
