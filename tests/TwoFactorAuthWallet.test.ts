import Web3 from 'web3'
import { ethers, network } from 'hardhat'
import { expect } from 'chai'

const target = '0x3078303030303030303030303030303030303031'
const value = 0
const data = '0x1234'

const ZERO_IN_BYTES32 = '0x' + '0'.repeat(64)

describe("Two Factor Auth Wallet", () => {

  describe('#executeWithSignature', () => {

    const signerAccount = createNewAccount()
    const packedMessage = ethers.utils.solidityPack(["address", "uint256", "bytes"], [target, value, data])
    const { v, r, s } = hashAndSignWithPrivateKey(packedMessage, signerAccount.privateKey)

    it('should execute the transaction if the signature is ok', async () => {
      const [owner] = await ethers.getSigners();
      const twoFactorAuthWallet = await ethers.getContractFactory("TwoFactorAuthWallet");
      const twoFactorAuthWalletContract = await twoFactorAuthWallet.deploy(owner.address, signerAccount.address);
      await twoFactorAuthWalletContract.deployed();
  
      await twoFactorAuthWalletContract.executeWithSignature(target, value, data, {v, r, s})
    })
  
    it('should fail if the signature is from other account', async () => {
      const [owner] = await ethers.getSigners();
      const twoFactorAuthWallet = await ethers.getContractFactory("TwoFactorAuthWallet");
      const twoFactorAuthWalletContract = await twoFactorAuthWallet.deploy(owner.address, owner.address);
      await twoFactorAuthWalletContract.deployed();
  
      await (expect(twoFactorAuthWalletContract.executeWithSignature(target, value, data, {v, r, s})))
        .to.be.revertedWith('Invalid signature')
    })
  
    it('should fail if the sender is not the owner', async () => {
      const [owner] = await ethers.getSigners();
      const twoFactorAuthWallet = await ethers.getContractFactory("TwoFactorAuthWallet");
      const twoFactorAuthWalletContract = await twoFactorAuthWallet.deploy(signerAccount.address, signerAccount.address);
      await twoFactorAuthWalletContract.deployed();
  
      await (expect(twoFactorAuthWalletContract.executeWithSignature(target, value, data, {v, r, s})))
        .to.be.revertedWith('2FA: Only owner')
    })
  })

  describe('Pending transaction flow', () => {
    it('emit PendingTransactionAdded events', async () => {
      const [owner] = await ethers.getSigners();
      const twoFactorAuthWallet = await ethers.getContractFactory("TwoFactorAuthWallet");
      const twoFactorAuthWalletContract = await twoFactorAuthWallet.deploy(owner.address, owner.address);
      await twoFactorAuthWalletContract.deployed();

      const blockNumBefore = await ethers.provider.getBlockNumber();
      const blockBefore = await ethers.provider.getBlock(blockNumBefore);
      const currentTimestamp = blockBefore.timestamp + 1;

      await expect(twoFactorAuthWalletContract.addPendingTransaction(target, value, data))
      .to.emit(twoFactorAuthWalletContract, "PendingTransactionAdded").withArgs([
        target, value, data, currentTimestamp, false
      ], 0);

      await expect(twoFactorAuthWalletContract.addPendingTransaction(target, value, data))
      .to.emit(twoFactorAuthWalletContract, "PendingTransactionAdded").withArgs([
        target, value, data, currentTimestamp + 1, false
      ], 1);
    })

    it(`rejects the execution if time hasn't passed or already executed`, async () => {
      const [owner] = await ethers.getSigners();
      const twoFactorAuthWallet = await ethers.getContractFactory("TwoFactorAuthWallet");
      const twoFactorAuthWalletContract = await twoFactorAuthWallet.deploy(owner.address, owner.address);
      await twoFactorAuthWalletContract.deployed();

      await twoFactorAuthWalletContract.addPendingTransaction(target, value, data)
      
      await expect(twoFactorAuthWalletContract.executePendingTransaction(0))
        .to.be.revertedWith('Must wait before executing the transaction')

      await passTime(2000)

      await expect(twoFactorAuthWalletContract.executePendingTransaction(0))
        .to.not.be.reverted

        await expect(twoFactorAuthWalletContract.executePendingTransaction(0))
        .to.be.revertedWith('Transaction already executed')
    })

    it(`rejects the execution if the transaction was revoked`, async () => {
      const [owner] = await ethers.getSigners();
      const twoFactorAuthWallet = await ethers.getContractFactory("TwoFactorAuthWallet");
      const twoFactorAuthWalletContract = await twoFactorAuthWallet.deploy(owner.address, owner.address);
      await twoFactorAuthWalletContract.deployed();

      await twoFactorAuthWalletContract.addPendingTransaction(target, value, data)

      await twoFactorAuthWalletContract.revokePendingTransaction(0)

      await expect(twoFactorAuthWalletContract.executePendingTransaction(0))
        .to.be.revertedWith('Transaction already executed')
    })
  })

});


async function passTime(time: number) {
  await network.provider.send("evm_increaseTime", [time])
}

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