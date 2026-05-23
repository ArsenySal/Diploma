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
    2 * c.pairingExternalCost +
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
    2 * c.pairingCircuitCost +
    openedValues * 45;

  const ipaCircuitVerifier =
    params.logN * c.curveCircuitCost +
    openedValues * 70;

  const friCircuitVerifier =
    params.friQueries * params.logN * 2 * c.hashCircuitCost +
    params.friQueries * friLayers * 25 +
    openedValues * 35;

  return {
    kzg: {
      proofBytes: Math.round(kzgProofBytes),
      proverCost: Math.round(kzgProver),
      externalVerifierCost: Math.round(kzgExternalVerifier),
      circuitVerifierCost: Math.round(kzgCircuitVerifier),
      commitmentBytes: params.polynomialCount * c.kzgGroupBytes
    },
    ipa: {
      proofBytes: Math.round(ipaProofBytes),
      proverCost: Math.round(ipaProver),
      externalVerifierCost: Math.round(ipaExternalVerifier),
      circuitVerifierCost: Math.round(ipaCircuitVerifier),
      commitmentBytes: params.polynomialCount * c.ipaGroupBytes
    },
    fri: {
      proofBytes: Math.round(friProofBytes),
      proverCost: Math.round(friProver),
      externalVerifierCost: Math.round(friExternalVerifier),
      circuitVerifierCost: Math.round(friCircuitVerifier),
      commitmentBytes: params.polynomialCount * c.hashBytes
    }
  };
}

function scoreSchemes(params, estimates) {
  const baseScores = {
    kzg: 70,
    ipa: 70,
    fri: 70
  };

  const priorityScores = getPriorityScores(params.priority, params.trustedSetupAllowed);

  const scores = {
    kzg: baseScores.kzg + priorityScores.kzg,
    ipa: baseScores.ipa + priorityScores.ipa,
    fri: baseScores.fri + priorityScores.fri
  };

  if (!params.trustedSetupAllowed) {
    scores.kzg -= 45;
    scores.ipa += 8;
    scores.fri += 12;
  }

  if (params.recursionRequired) {
    scores.kzg -= 35;
    scores.ipa += 28;
    scores.fri += 6;
  }

  if (params.transparencyRequired) {
    scores.kzg -= 55;
    scores.ipa -= 15;
    scores.fri += 38;
  }

  addModelTieBreakers(scores, estimates, params);

  return {
    kzg: { score: clamp(Math.round(scores.kzg), 0, 100) },
    ipa: { score: clamp(Math.round(scores.ipa), 0, 100) },
    fri: { score: clamp(Math.round(scores.fri), 0, 100) }
  };
}

function getPriorityScores(priority, trustedSetupAllowed) {
  const presets = {
    balanced: {
      kzg: trustedSetupAllowed ? 12 : -10,
      ipa: 10,
      fri: 8
    },
    proofSize: {
      kzg: trustedSetupAllowed ? 30 : -25,
      ipa: 4,
      fri: -18
    },
    verifierCost: {
      kzg: trustedSetupAllowed ? 26 : -20,
      ipa: 8,
      fri: -8
    },
    proverCost: {
      kzg: 8,
      ipa: 10,
      fri: -4
    },
    noTrustedSetup: {
      kzg: -35,
      ipa: 20,
      fri: 26
    },
    recursion: {
      kzg: -18,
      ipa: 32,
      fri: 5
    },
    transparency: {
      kzg: -35,
      ipa: -8,
      fri: 36
    }
  };

  return presets[priority] ?? presets.balanced;
}

function addModelTieBreakers(scores, estimates, params) {
  const schemes = ["kzg", "ipa", "fri"];

  const proofMin = Math.min(...schemes.map((id) => estimates[id].proofBytes));
  const proverMin = Math.min(...schemes.map((id) => estimates[id].proverCost));
  const externalVerifierMin = Math.min(...schemes.map((id) => estimates[id].externalVerifierCost));
  const circuitVerifierMin = Math.min(...schemes.map((id) => estimates[id].circuitVerifierCost));

  for (const id of schemes) {
    if (estimates[id].proofBytes === proofMin) scores[id] += 5;
    if (estimates[id].proverCost === proverMin) scores[id] += 3;
    if (estimates[id].externalVerifierCost === externalVerifierMin) scores[id] += 4;
    if (params.recursionRequired && estimates[id].circuitVerifierCost === circuitVerifierMin) scores[id] += 6;
  }

  if (params.priority === "proofSize" && params.trustedSetupAllowed && !params.recursionRequired && !params.transparencyRequired) {
    scores.kzg = Math.max(scores.kzg, scores.ipa + 8, scores.fri + 20);
  }

  if (params.priority === "verifierCost" && params.trustedSetupAllowed && !params.recursionRequired && !params.transparencyRequired) {
    scores.kzg = Math.max(scores.kzg, scores.ipa + 6, scores.fri + 14);
  }

  if ((params.priority === "recursion" || params.recursionRequired) && !params.transparencyRequired) {
    scores.ipa = Math.max(scores.ipa, scores.kzg + 12, scores.fri + 8);
  }

  if (params.priority === "transparency" || params.transparencyRequired) {
    scores.fri = Math.max(scores.fri, scores.kzg + 18, scores.ipa + 10);
  }

  if (params.priority === "noTrustedSetup" && !params.recursionRequired) {
    scores.fri = Math.max(scores.fri, scores.kzg + 20);
    scores.ipa = Math.max(scores.ipa, scores.kzg + 12);
  }
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
      <td>${formatNumber(estimate.externalVerifierCost)}</td>
      <td>${formatNumber(estimate.circuitVerifierCost)}</td>
      <td>${scheme.setup}</td>
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
  recommendationTextElement.textContent = buildRecommendationText(best.id);
}

function buildRecommendationText(schemeId) {
  if (schemeId === "kzg") {
    return "KZG выбран потому, что в этом сценарии важнее constant-size opening, компактный proof, сильный батчинг и короткая внешняя проверка. Это корректно при допущении trusted setup и pairing-friendly кривых.";
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
