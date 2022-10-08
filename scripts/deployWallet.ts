import { ethers } from "hardhat";

async function main() {
  const factory = await ethers.getContractFactory("TwoFactorAuthWallet");

  console.log(await factory.signer.getAddress());

  const wallet = await factory.deploy(
    "0x9bb91E9AA81bAb8027E34C0C36c4f2Acee720168",
    "0x9bb91E9AA81bAb8027E34C0C36c4f2Acee720168"
  );
  const deploy = await wallet.deployed();

  console.info(
    `TwoFactorAuthWallet deployed to ${deploy.address} in tx ${deploy.deployTransaction.hash}`
  );
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
