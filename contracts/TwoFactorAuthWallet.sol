// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract TwoFactorAuthWallet {
    address public owner;
    address public authenticatorSigner;
    uint256 public _nonce;

    uint256 public timeToWaitForPendingTransactions = 60 * 60 * 24 * 3; // 3 days

    PendingTransaction[] public pendingTransactions;
    ExtraSigner public extraSigner;

    struct ExtraSigner {
        address signer;
        uint256 validUntil;
    }

    struct Signature {
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    struct PendingTransaction {
        address target;
        uint256 value;
        bytes data;
        uint256 createdAt;
        bool executed;
    }

    struct TransactionParams {
        address target;
        uint256 value;
        bytes data;
    }

    event PendingTransactionAdded(PendingTransaction pendingTransation, uint256 index);  

    // solhint-disable-next-line no-empty-blocks
    receive() external payable {}

    modifier onlyOwner() {
        require(msg.sender == owner, "2FA: Only owner");
        _;
    }

    modifier onlyInternal() {
        require(msg.sender == address(this), "Only internal calls");
        _;
    }

    constructor(address _owner, address _authenticatorSigner) {
        owner = _owner;
        authenticatorSigner = _authenticatorSigner;
        extraSigner.signer = address(0);
    }

    function nonce() public view returns (uint256) {
        return _nonce;
    }

    function setTimeToWait(uint256 timeToWaitInSeconds) public onlyInternal {
        timeToWaitForPendingTransactions = timeToWaitInSeconds;
    }

    function setNewSigner(address signer, uint256 timeToOverrideInSecond) public onlyInternal {
        extraSigner.signer = signer;
        extraSigner.validUntil = block.timestamp + timeToOverrideInSecond;
    }

    function revokePendingTransaction(uint256 index) public onlyOwner {
        PendingTransaction storage pendingTransaction = pendingTransactions[index];
        pendingTransaction.executed = true;
    }

    function executePendingTransaction(uint256 index) public onlyOwner {
        PendingTransaction storage pendingTransaction = pendingTransactions[index];
        require(!pendingTransaction.executed,
            "Transaction already executed");
        require(pendingTransaction.createdAt + timeToWaitForPendingTransactions < block.timestamp,
            "Must wait before executing the transaction");
        pendingTransaction.executed = true;
        _call(
            pendingTransaction.target,
            pendingTransaction.value,
            pendingTransaction.data);
    }

    function addPendingTransaction(
        address target,
        uint256 value,
        bytes calldata data) public onlyOwner {
        PendingTransaction memory pendingTransaction = PendingTransaction(target, value, data, block.timestamp, false);
        pendingTransactions.push(pendingTransaction);
        emit PendingTransactionAdded(pendingTransaction, pendingTransactions.length - 1);
    }

    function executeWithSignature(
        address target,
        uint256 value,
        bytes calldata data,
        Signature calldata signature
    ) public onlyOwner {
        bytes32 hashedMessage = keccak256(abi.encodePacked(target, value, data));
        validateSignature(hashedMessage, signature);
        _call(target, value, data);
    }

    function _call(
        address target,
        uint256 value,
        bytes memory data
    ) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    function getSignerAddress(bytes32 hashedMessage, Signature calldata signature) internal pure returns (address) {
        bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        bytes32 prefixedHashMessage = keccak256(abi.encodePacked(prefix, hashedMessage));
        address signer = ecrecover(prefixedHashMessage, signature.v, signature.r, signature.s);
        return signer;
    }

    function validateSignature(bytes32 hashedMessage, Signature calldata signature) internal view {
        address signerAddress = getSignerAddress(hashedMessage, signature);

        if (signerAddress == authenticatorSigner) {
            return;
        }

        if (signerAddress == extraSigner.signer && block.timestamp < extraSigner.validUntil) {
            return;
        }

        revert("Invalid signature");
    }
}
