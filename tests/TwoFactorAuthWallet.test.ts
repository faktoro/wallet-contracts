import { expect } from "chai";
import { ethers } from "hardhat";
import Web3 from 'web3'

const ownerAddress = '0x3078303030303030303030303030303030303030'

describe("Two Factor Auth Wallet", () => {

  it("Should return the signer address when verifying signature", async () => {

    const newAccount = createNewAccount()
    const { message, v, r, s } = hashAndSignWithPrivateKey('message', newAccount.privateKey)

    const twoFactorAuthWallet = await ethers.getContractFactory("TwoFactorAuthWallet");
    const twoFactorAuthWalletContract = await twoFactorAuthWallet.deploy(ownerAddress, newAccount.address);
    await twoFactorAuthWalletContract.deployed();
    
    await createNewAccount()
    const address = await twoFactorAuthWalletContract.verifyMessage(message, v, r, s)

    expect(address).to.equal(newAccount.address)
  });
});


function getWeb3() {
  return new Web3(new Web3.providers.HttpProvider(''))
}

function createNewAccount() {
  return getWeb3().eth.accounts.create();
}

function hashAndSignWithPrivateKey(message: string, privateKey: string) {
  const web3 = getWeb3()
  const hashedMessage = web3.eth.accounts.hashMessage(message);
  return web3.eth.accounts.sign(hashedMessage, privateKey)
}