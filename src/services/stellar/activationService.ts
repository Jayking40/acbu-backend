import { Keypair, Operation, TransactionBuilder } from "@stellar/stellar-sdk";
import { stellarClient } from "./client";
import { getBaseFee } from "./feeManager";
import { config } from "../../config/env";

export async function ensureAccountActivated(
  destination: string,
): Promise<{ created: boolean; txHash?: string }> {
  const server = stellarClient.getServer();
  try {
    await server.loadAccount(destination);
    return { created: false };
  } catch (e: any) {
    if (e?.response?.status !== 404) throw e;
  }

  const backendKp = stellarClient.getKeypair();
  if (!backendKp) {
    throw new Error("No Stellar source account (STELLAR_SECRET_KEY)");
  }

  const sourceAccount = await server.loadAccount(backendKp.publicKey());
  const op = Operation.createAccount({
    destination,
    startingBalance: String(config.stellar.minBalanceXlm || 1),
  });

  const tx = new TransactionBuilder(sourceAccount, {
    fee: await getBaseFee(),
    networkPassphrase: stellarClient.getNetworkPassphrase(),
  })
    .addOperation(op)
    .setTimeout(0)
    .build();

  tx.sign(Keypair.fromSecret(backendKp.secret()));
  const res = await server.submitTransaction(tx);
  return { created: true, txHash: res.hash };
}
