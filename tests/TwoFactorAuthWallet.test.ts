import Web3 from 'web3'
import { ethers, network } from 'hardhat'
import { expect } from 'chai'
import { deployMockContract } from 'ethereum-waffle'

import erc20Abi from './abi/erc20.json'
import twoFactorAuthWalletAbi from '../artifacts/contracts/TwoFactorAuthWallet.sol/TwoFactorAuthWallet.json'

const target = '0x3078303030303030303030303030303030303031'
const value = 0
const data = '0x1234'

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

    it('should fail if the transaction is reverted', async () => {
      const [owner] = await ethers.getSigners();
      const erc20MockContract = await deployMockContract(owner, erc20Abi);

      const _target = erc20MockContract.address
      const _value = 0
      const _data = getCallData(erc20Abi, 'transfer', [target, 100])

      const packedMessage = ethers.utils.solidityPack(["address", "uint256", "bytes"], [_target, _value, _data])
      const { v, r, s } = hashAndSignWithPrivateKey(packedMessage, signerAccount.privateKey)

      const revertedReason = 'Reverted by test'
      await erc20MockContract.mock.transfer.withArgs(target, 100).revertsWithReason(revertedReason);
      
      const twoFactorAuthWallet = await ethers.getContractFactory("TwoFactorAuthWallet");
      const twoFactorAuthWalletContract = await twoFactorAuthWallet.deploy(owner.address, signerAccount.address);
      await twoFactorAuthWalletContract.deployed();
  
      await (expect(twoFactorAuthWalletContract.executeWithSignature(_target, _value, _data, {v, r, s})))
        .to.be.revertedWith(revertedReason)
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

      const currentTimestamp = 1 + await lastBlockTimestamp()

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

      await passTime(60 * 60 * 24 * 3 + 1)

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

  describe('setNewSigner', () => {
    it('should set new signer via executeWithSignature', async () => {
      const authenticatorAccount = createNewAccount()
      const newSignerAccount = createNewAccount()
      const [owner] = await ethers.getSigners();
      const twoFactorAuthWallet = await ethers.getContractFactory("TwoFactorAuthWallet");
      const twoFactorAuthWalletContract = await twoFactorAuthWallet.deploy(owner.address, authenticatorAccount.address);

      const validFor = 1000

      const target = twoFactorAuthWalletContract.address
      const value = 0
      const data = getCallData(twoFactorAuthWalletAbi.abi, 'setNewSigner', [newSignerAccount.address, validFor])

      const packedMessage = ethers.utils.solidityPack(["address", "uint256", "bytes"], [target, value, data])

      const currentTimestamp = 1 + await lastBlockTimestamp()

      // No extra signer is defined
      const defaultExtraSigner = await twoFactorAuthWalletContract.extraSigner()
      expect(defaultExtraSigner.signer).to.equal('0x0000000000000000000000000000000000000000')

      // It should revert transactions signed with newSignerAccount
      await (expect(twoFactorAuthWalletContract.executeWithSignature(target, value, data, 
        hashAndSignWithPrivateKey(packedMessage, newSignerAccount.privateKey))))
        .to.be.revertedWith('Invalid signature')
      
      await twoFactorAuthWalletContract.executeWithSignature(target, value, data,
        hashAndSignWithPrivateKey(packedMessage, authenticatorAccount.privateKey))

      // The extra signer is defined after setting it
      const newExtraSigner = await twoFactorAuthWalletContract.extraSigner()
      expect(newExtraSigner.signer).to.equal(newSignerAccount.address)
      expect(newExtraSigner.validUntil).to.equal(currentTimestamp + validFor + 1)

      // Now, it shouldn't revert transactions signed with newSignerAccount
      await (expect(twoFactorAuthWalletContract.executeWithSignature(target, value, data, 
        hashAndSignWithPrivateKey(packedMessage, newSignerAccount.privateKey))))
        .to.not.be.reverted

      await passTime(validFor + 1)

      // After the expected time, it should revert transactions signed with newSignerAccount
      await (expect(twoFactorAuthWalletContract.executeWithSignature(target, value, data, 
        hashAndSignWithPrivateKey(packedMessage, newSignerAccount.privateKey))))
        .to.be.revertedWith('Invalid signature')
    })

    it('should set new signer via pending Transaction', async () => {
      const authenticatorAccount = createNewAccount()
      const newSignerAccount = createNewAccount()
      const [owner] = await ethers.getSigners();
      const twoFactorAuthWallet = await ethers.getContractFactory("TwoFactorAuthWallet");
      const twoFactorAuthWalletContract = await twoFactorAuthWallet.deploy(owner.address, authenticatorAccount.address);

      const validFor = 1000

      const target = twoFactorAuthWalletContract.address
      const value = 0
      const data = getCallData(twoFactorAuthWalletAbi.abi, 'setNewSigner', [newSignerAccount.address, validFor])

      const packedMessage = ethers.utils.solidityPack(["address", "uint256", "bytes"], [target, value, data])

      await twoFactorAuthWalletContract.addPendingTransaction(target, value, data)
      
      // Waits until pending transaction can be executed
      await passTime(60 * 60 * 24 * 3 + 1)

      // No extra signer is defined
      const defaultExtraSigner = await twoFactorAuthWalletContract.extraSigner()
      expect(defaultExtraSigner.signer).to.equal('0x0000000000000000000000000000000000000000')

      // It should revert transactions signed with newSignerAccount
      await (expect(twoFactorAuthWalletContract.executeWithSignature(target, value, data, 
        hashAndSignWithPrivateKey(packedMessage, newSignerAccount.privateKey))))
        .to.be.revertedWith('Invalid signature')
        
      await twoFactorAuthWalletContract.executePendingTransaction(0)

      // The extra signer is defined after setting it
      const newExtraSigner = await twoFactorAuthWalletContract.extraSigner()
      expect(newExtraSigner.signer).to.equal(newSignerAccount.address)

      // Now, it shouldn't revert transactions signed with newSignerAccount
      await (expect(twoFactorAuthWalletContract.executeWithSignature(target, value, data, 
        hashAndSignWithPrivateKey(packedMessage, newSignerAccount.privateKey))))
        .to.not.be.reverted

      await passTime(validFor + 1)

      // After the expected time, it should revert transactions signed with newSignerAccount
      await (expect(twoFactorAuthWalletContract.executeWithSignature(target, value, data, 
        hashAndSignWithPrivateKey(packedMessage, newSignerAccount.privateKey))))
        .to.be.revertedWith('Invalid signature')
    })

    it(`shouldn't allow to call setNewSigner directly`, async () => {
      const authenticatorAccount = createNewAccount()
      const newSignerAccount = createNewAccount()
      const [owner] = await ethers.getSigners();
      const twoFactorAuthWallet = await ethers.getContractFactory("TwoFactorAuthWallet");
      const twoFactorAuthWalletContract = await twoFactorAuthWallet.deploy(owner.address, authenticatorAccount.address);

      await (expect(twoFactorAuthWalletContract.setNewSigner(newSignerAccount.address, 100))
        .to.be.revertedWith('Only internal calls'))
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

function getCallData(abi: any, functionName: string, args: any) {
  const contractInterface = new ethers.utils.Interface(abi)
  return contractInterface.encodeFunctionData(functionName, args ?? [])
}

async function lastBlockTimestamp() {
  const blockNumBefore = await ethers.provider.getBlockNumber();
  const blockBefore = await ethers.provider.getBlock(blockNumBefore);
  return blockBefore.timestamp;
}