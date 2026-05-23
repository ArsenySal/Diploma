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
    params.polynomialCount * params.n * 1.2 +
    openedValues * params.n * 0.14;

  const ipaProver =
    params.polynomialCount * params.n * 1.15 +
    params.polynomialCount * params.logN * 340 +
    openedValues * params.logN * 120;

  const friProver =
    params.polynomialCount * params.n * params.blowupFactor * 0.5 +
    params.polynomialCount * params.n * params.logN * 0.1 +
    params.polynomialCount * params.n * params.blowupFactor * c.hashUnit;

  const kzgExternalVerifier =
    2 * 720 +
    openedValues * 8 +
    params.polynomialCount * 4;

  const ipaExternalVerifier =
    params.logN * 92 +
    openedValues * 22 +
    params.polynomialCount * 14;

  const friExternalVerifier =
    params.friQueries * params.logN * 2 * c.hashUnit * 55 +
    params.friQueries * friLayers * c.fieldUnit * 55 +
    openedValues * 9;

  const kzgCircuitVerifier =
    24000 +
    openedValues * 45;

  const ipaCircuitVerifier =
    params.logN * 520 +
    openedValues * 70;

  const friCircuitVerifier =
    params.friQueries * params.logN * 2 * 95 +
    params.friQueries * friLayers * 25 +
    openedValues * 35;

  return {
    kzg: {
      proofBytes: Math.round(kzgProofBytes),
      proverCost: Math.round(kzgProver),
      verifierCost: Math.round(kzgExternalVerifier),
      circuitVerifierCost: Math.round(kzgCircuitVerifier),
      commitmentBytes: params.polynomialCount * c.kzgGroupBytes
    },
    ipa: {
      proofBytes: Math.round(ipaProofBytes),
      proverCost: Math.round(ipaProver),
      verifierCost: Math.round(ipaExternalVerifier),
      circuitVerifierCost: Math.round(ipaCircuitVerifier),
      commitmentBytes: params.polynomialCount * c.ipaGroupBytes
    },
    fri: {
      proofBytes: Math.round(friProofBytes),
      proverCost: Math.round(friProver),
      verifierCost: Math.round(friExternalVerifier),
      circuitVerifierCost: Math.round(friCircuitVerifier),
      commitmentBytes: params.polynomialCount * c.hashBytes
    }
  };
}

function normalizeCost(value, allValues) {
  const min = Math.min(...allValues);
  const max = Math.max(...allValues);
  if (max === min) return 100;
  return 100 - ((value - min) / (max - min)) * 45;
}

function scoreSchemes(params, estimates) {
  const proofValues = SCHEMES.map((scheme) => estimates[scheme.id].proofBytes);
  const proverValues = SCHEMES.map((scheme) => estimates[scheme.id].proverCost);
  const externalVerifierValues = SCHEMES.map((scheme) => estimates[scheme.id].verifierCost);
  const circuitVerifierValues = SCHEMES.map((scheme) => estimates[scheme.id].circuitVerifierCost);

  const quality = {
    kzg: {
      compactOpening: 100,
      externalVerification: 95,
      inCircuitVerification: normalizeCost(estimates.kzg.circuitVerifierCost, circuitVerifierValues) - 25,
      proverPracticality: normalizeCost(estimates.kzg.proverCost, proverValues),
      proofModel: normalizeCost(estimates.kzg.proofBytes, proofValues),
      noTrustedSetup: 20,
      recursion: 35,
      transparency: 10,
      batching: 96
    },
    ipa: {
      compactOpening: 72,
      externalVerification: 76,
      inCircuitVerification: normalizeCost(estimates.ipa.circuitVerifierCost, circuitVerifierValues),
      proverPracticality: normalizeCost(estimates.ipa.proverCost, proverValues),
      proofModel: normalizeCost(estimates.ipa.proofBytes, proofValues),
      noTrustedSetup: 86,
      recursion: 92,
      transparency: 62,
      batching: 78
    },
    fri: {
      compactOpening: 40,
      externalVerification: 62,
      inCircuitVerification: normalizeCost(estimates.fri.circuitVerifierCost, circuitVerifierValues),
      proverPracticality: normalizeCost(estimates.fri.proverCost, proverValues),
      proofModel: normalizeCost(estimates.fri.proofBytes, proofValues),
      noTrustedSetup: 100,
      recursion: 60,
      transparency: 100,
      batching: 66
    }
  };

  const weights = getWeights(params);
  const result = {};

  for (const scheme of SCHEMES) {
    const q = quality[scheme.id];

    let total =
      q.compactOpening * weights.compactOpening +
      q.externalVerification * weights.externalVerification +
      q.inCircuitVerification * weights.inCircuitVerification +
      q.proverPracticality * weights.proverPracticality +
      q.proofModel * weights.proofModel +
      q.noTrustedSetup * weights.noTrustedSetup +
      q.recursion * weights.recursion +
      q.transparency * weights.transparency +
      q.batching * weights.batching;

    total += scenarioAdjustment(scheme.id, params);

    result[scheme.id] = {
      score: Math.max(0, Math.min(100, Math.round(total))),
      components: q
    };
  }

  return result;
}

function getWeights(params) {
  const presets = {
    balanced: {
      compactOpening: 0.20,
      externalVerification: 0.18,
      inCircuitVerification: 0.04,
      proverPracticality: 0.10,
      proofModel: 0.12,
      noTrustedSetup: 0.10,
      recursion: 0.08,
      transparency: 0.06,
      batching: 0.12
    },
    proofSize: {
      compactOpening: 0.42,
      externalVerification: 0.15,
      inCircuitVerification: 0.02,
      proverPracticality: 0.06,
      proofModel: 0.20,
      noTrustedSetup: 0.03,
      recursion: 0.02,
      transparency: 0.02,
      batching: 0.08
    },
    verifierCost: {
      compactOpening: 0.12,
      externalVerification: 0.46,
      inCircuitVerification: 0.06,
      proverPracticality: 0.06,
      proofModel: 0.10,
      noTrustedSetup: 0.05,
      recursion: 0.04,
      transparency: 0.03,
      batching: 0.08
    },
    proverCost: {
      compactOpening: 0.08,
      externalVerification: 0.08,
      inCircuitVerification: 0.04,
      proverPracticality: 0.44,
      proofModel: 0.12,
      noTrustedSetup: 0.06,
      recursion: 0.06,
      transparency: 0.04,
      batching: 0.08
    },
    noTrustedSetup: {
      compactOpening: 0.08,
      externalVerification: 0.08,
      inCircuitVerification: 0.08,
      proverPracticality: 0.08,
      proofModel: 0.08,
      noTrustedSetup: 0.42,
      recursion: 0.08,
      transparency: 0.05,
      batching: 0.05
    },
    recursion: {
      compactOpening: 0.07,
      externalVerification: 0.06,
      inCircuitVerification: 0.28,
      proverPracticality: 0.08,
      proofModel: 0.09,
      noTrustedSetup: 0.10,
      recursion: 0.26,
      transparency: 0.03,
      batching: 0.03
    },
    transparency: {
      compactOpening: 0.04,
      externalVerification: 0.06,
      inCircuitVerification: 0.08,
      proverPracticality: 0.06,
      proofModel: 0.06,
      noTrustedSetup: 0.18,
      recursion: 0.06,
      transparency: 0.42,
      batching: 0.04
    }
  };

  return presets[params.priority] ?? presets.balanced;
}

function scenarioAdjustment(schemeId, params) {
  let adjustment = 0;

  if (params.priority === "proofSize" && schemeId === "kzg" && params.trustedSetupAllowed) {
    adjustment += 8;
  }

  if (params.priority === "verifierCost" && schemeId === "kzg" && !params.recursionRequired) {
    adjustment += 6;
  }

  if (params.priority === "recursion" && schemeId === "ipa") {
    adjustment += 8;
  }

  if (params.priority === "transparency" && schemeId === "fri") {
    adjustment += 10;
  }

  if (params.priority === "noTrustedSetup" && schemeId === "kzg") {
    adjustment -= 30;
  }

  if (!params.trustedSetupAllowed && schemeId === "kzg") {
    adjustment -= 38;
  }

  if (!params.trustedSetupAllowed && schemeId === "ipa") {
    adjustment += 4;
  }

  if (!params.trustedSetupAllowed && schemeId === "fri") {
    adjustment += 6;
  }

  if (params.recursionRequired && schemeId === "kzg") {
    adjustment -= 26;
  }

  if (params.recursionRequired && schemeId === "ipa") {
    adjustment += 10;
  }

  if (params.recursionRequired && schemeId === "fri") {
    adjustment -= 2;
  }

  if (params.transparencyRequired && schemeId === "fri") {
    adjustment += 16;
  }

  if (params.transparencyRequired && schemeId === "ipa") {
    adjustment -= 22;
  }

  if (params.transparencyRequired && schemeId === "kzg") {
    adjustment -= 50;
  }

  return adjustment;
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
    return "KZG выбран потому, что в этом сценарии важнее compact opening, эффективный батчинг и короткая внешняя проверка. Это корректно только при допущении trusted setup и pairing-friendly кривых.";
  }

  if (schemeId === "ipa") {
    return "IPA выбран потому, что сценарий лучше согласуется с pairing-free verifier, отсутствием toxic waste и рекурсивной проверкой. Это не означает минимальный proof size: открытие остается логарифмическим.";
  }

  if (schemeId === "fri") {
    return "FRI выбран потому, что в сценарии важны прозрачность, отсутствие SRS и STARK-like модель. Цена такого выбора — более крупный proof и hash-heavy verification.";
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
