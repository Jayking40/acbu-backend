declare var process: any;
import { prisma } from "../src/config/database";
import { ingestMetricsAndProposeWeights } from "../src/services/metrics/metricsService";

async function main() {
  console.log("Starting basket weight computation...");
  
  // 1. Get current period
  const now = new Date();
  const y = now.getUTCFullYear();
  const m = String(now.getUTCMonth() + 1).padStart(2, "0");
  const period = `${y}-${m}`;

  // 2. Compute and propose weights
  console.log(`Ingesting metrics and computing weights for period: ${period}`);
  await ingestMetricsAndProposeWeights(period);

  // 3. Fetch the updated metrics and proposed weights
  const metrics = await prisma.basketMetrics.findMany({
    where: { period },
  });

  const proposedConfigs = await prisma.basketConfig.findMany({
    // Fetch proposals created recently (today)
    where: { status: "proposed", effectiveFrom: { gte: new Date(new Date().setHours(0,0,0,0)) } },
    orderBy: { weight: "desc" },
  });

  // 4. Generate report
  console.log("\n===========================================================================");
  console.log(`               B A S K E T   W E I G H T S   R E P O R T  (${period}) `);
  console.log("===========================================================================\n");

  console.log("Factors Considered:");
  console.log("- GDP (40% weight): Macroeconomic size (Sourced from World Bank API)");
  console.log("- Trade Volume (30% weight): Platform usage (Sourced from token burns)");
  console.log("- Liquidity (30% weight): Market depth (Baseline default)\n");

  const reportData = proposedConfigs.map((config: any) => {
    const metric = metrics.find((m: any) => m.currency === config.currency);
    const rawValues = metric?.rawValues as Record<string, any> | undefined;
    const rawGdp = rawValues?.gdpUsd ? `$${Number(rawValues.gdpUsd).toLocaleString()}` : "N/A";
    const rawTrade = rawValues?.tradeVolume ? Number(rawValues.tradeVolume).toLocaleString() : "0";
    
    return {
      Currency: config.currency,
      "Proposed Weight": config.weight.toNumber().toFixed(4),
      "GDP Score": metric?.gdpScore?.toNumber().toFixed(2) || "0.00",
      "Trade Score": metric?.tradeScore?.toNumber().toFixed(2) || "0.00",
      "Liquidity Score": metric?.liquidityScore?.toNumber().toFixed(2) || "0.00",
      "Raw GDP (USD)": rawGdp,
      "Raw Trade Vol": rawTrade
    };
  });

  console.table(reportData);

  console.log("\nComputation complete. Weights have been proposed and stored in the database.");
}

main()
  .catch((e: any) => {
    console.error("Error computing basket weights:", e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
    process.exit(0);
  });
