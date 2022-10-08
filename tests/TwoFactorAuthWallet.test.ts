import Web3 from 'web3'
import { ethers } from 'hardhat'
import { expect } from 'chai'

const target = '0x3078303030303030303030303030303030303031'
const value = 0
const data = 1234

describe("Two Factor Auth Wallet", () => {

  it('should execute the transaction if the signature is ok', async () => {
    const [owner] = await ethers.getSigners();
    const signerAccount = createNewAccount()
    const packedMessage = ethers.utils.solidityPack(["address", "uint256", "bytes"], [target, value, data])
    const { v, r, s } = hashAndSignWithPrivateKey(packedMessage, signerAccount.privateKey)

    const twoFactorAuthWallet = await ethers.getContractFactory("TwoFactorAuthWallet");
    const twoFactorAuthWalletContract = await twoFactorAuthWallet.deploy(owner.address, signerAccount.address);
    await twoFactorAuthWalletContract.deployed();

    await twoFactorAuthWalletContract.exec(target, value, data, {v, r, s})
  })

  it('should fail if the signature is from other account', async () => {
    const [owner] = await ethers.getSigners();
    const signerAccount = createNewAccount()
    const packedMessage = ethers.utils.solidityPack(["address", "uint256", "bytes"], [target, value, data])
    const { v, r, s } = hashAndSignWithPrivateKey(packedMessage, signerAccount.privateKey)

    const twoFactorAuthWallet = await ethers.getContractFactory("TwoFactorAuthWallet");
    const twoFactorAuthWalletContract = await twoFactorAuthWallet.deploy(owner.address, owner.address);
    await twoFactorAuthWalletContract.deployed();

    await (expect(twoFactorAuthWalletContract.exec(target, value, data, {v, r, s})))
      .to.be.revertedWith('Invalid signature')
  })

  it('should fail if the sender is not the owner', async () => {
    const [owner] = await ethers.getSigners();
    const signerAccount = createNewAccount()
    const packedMessage = ethers.utils.solidityPack(["address", "uint256", "bytes"], [target, value, data])
    const { v, r, s } = hashAndSignWithPrivateKey(packedMessage, signerAccount.privateKey)

    const twoFactorAuthWallet = await ethers.getContractFactory("TwoFactorAuthWallet");
    const twoFactorAuthWalletContract = await twoFactorAuthWallet.deploy(signerAccount.address, signerAccount.address);
    await twoFactorAuthWalletContract.deployed();

    await (expect(twoFactorAuthWalletContract.exec(target, value, data, {v, r, s})))
      .to.be.revertedWith('2FA: Only owner')
  })

});


function getWeb3() {
  return new Web3(new Web3.providers.HttpProvider(''))
}

function createNewAccount() {
  return getWeb3().eth.accounts.create();
}

function hashAndSignWithPrivateKey(message: string, privateKey: string) {
  const web3 = getWeb3()
  const hashedMessage = ethers.utils.keccak256(message)
  return web3.eth.accounts.sign(hashedMessage, privateKey)
}