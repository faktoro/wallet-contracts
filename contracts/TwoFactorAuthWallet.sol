// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

///
contract TwoFactorAuthWallet {
    address public owner;
    address public authenticatorSigner;
    uint256 public _nonce;

    // solhint-disable-next-line no-empty-blocks
    receive() external payable {}

    modifier onlyOwner() {
        require(msg.sender == owner, "2FA: Only owner");
        _;
    }

    constructor(address _owner, address _authenticatorSigner) {
        owner = _owner;
        authenticatorSigner = _authenticatorSigner;
    }

    function nonce() public view returns (uint256) {
        return _nonce;
    }

    function exec(
        address target,
        uint256 value,
        bytes calldata data
    ) external onlyOwner {
        //
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

    function verifyMessage(bytes32 _hashedMessage, uint8 _v, bytes32 _r, bytes32 _s) public pure returns (address) {
        bytes memory prefix = "\x19Ethereum Signed Message:\n32";
        bytes32 prefixedHashMessage = keccak256(abi.encodePacked(prefix, _hashedMessage));
        address signer = ecrecover(prefixedHashMessage, _v, _r, _s);
        return signer;
    }
}
