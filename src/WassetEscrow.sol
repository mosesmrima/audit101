// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/Context.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract WassetEscrow is Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    IERC20 public token;
    address public buyer;
    address public seller;
    uint256 public balance;
    uint256 public amount;
    uint256 public signatureNonce;

    mapping(bytes32 => bool) public invalidSignaturesHashes;

    bool public completed;
    bool public locked;
    bool public deposited;

    event FundsDeposited(uint256 amount);
    event FundsReleased(address indexed to, uint256 amount);
    event FundsRefunded(address indexed to, uint256 amount);
    event EscrowLocked(bool locked);
    event EscrowCompleted();
    event ApprovalRefunded(address indexed participant);
    event ApprovalRefundUndone(address indexed participant);
    event ApprovalReleased(address indexed participant);
    event ApprovalReleaseUndone(address indexed participant);

    constructor(
        address _token,
        address _buyer,
        address _seller,
        address _owner,
        uint256 _amount
    ) Ownable(_owner) {
        require(_amount > 0, "Price must be greater than 0");
        require(
            address(0) != _buyer && address(0) != _seller,
            "Buyer or seller address must not be zero address"
        );

        token = IERC20(_token);
        buyer = _buyer;
        seller = _seller;
        amount = _amount;
        balance = _amount;
        _transferOwnership(_owner);
    }

    modifier onlyParticipants() {
        require(_isParticipant(_msgSender()), "Caller is not a participant");
        _;
    }

    modifier notCompleted() {
        require(!completed, "The Escrow has been completed");
        _;
    }

    modifier notLocked() {
        require(!locked, "Escrow is locked");
        _;
    }

    function _isParticipant(address _participant) private view returns (bool) {
        return
            _participant == seller ||
            _participant == buyer ||
            _participant == owner();
    }

    function deposit() external notCompleted notLocked nonReentrant {
        require(!deposited, "Escrow is funded already");
        token.safeTransferFrom(msg.sender, address(this), amount);
        deposited = true;
        emit FundsDeposited(amount);
    }

    function releaseFunds(
        uint256 _amount,
        uint256 _nonce,
        bytes calldata _signature
    ) external notLocked notCompleted nonReentrant {
        bytes32 hash = calculateIntentHash(0, _nonce, _amount);

        address signer = _getSigner(hash, _signature);

        require(signer == buyer, "Only buyer can release funds");

        require(_isParticipantSignature(hash, _signature), "Invalid signature");

        invalidSignaturesHashes[hash] = true;

        _executeTransfer(seller, _amount);
    }

    function releaseFunds(
        uint256 _amount,
        uint256[] calldata _nonces,
        bytes[] calldata _signatures
    ) external notLocked notCompleted nonReentrant {
        require(
            _nonces.length == 2 && _signatures.length == 2,
            "Requires exactly two arguments"
        );

        bytes32 hash0 = calculateIntentHash(0, _nonces[0], _amount);
        bytes32 hash1 = calculateIntentHash(0, _nonces[1], _amount);

        address signer0 = _getSigner(hash0, _signatures[0]);
        address signer1 = _getSigner(hash1, _signatures[1]);

        require(signer0 != signer1, "Duplicate signer");
        require(
            _isParticipantSignature(hash0, _signatures[0]) &&
                _isParticipantSignature(hash1, _signatures[1]),
            "Invalid signature"
        );

        invalidSignaturesHashes[hash0] = true;
        invalidSignaturesHashes[hash1] = true;

        _executeTransfer(seller, _amount);
    }

    function refundFunds(
        uint256 _amount,
        uint256 _nonce,
        bytes calldata _signature
    ) external notLocked notCompleted nonReentrant {
        bytes32 hash = calculateIntentHash(1, _nonce, _amount);

        address signer = _getSigner(hash, _signature);

        require(signer != seller, "Not seller");
        require(_isParticipantSignature(hash, _signature), "Invalid signature");

        invalidSignaturesHashes[hash] = true;

        _executeTransfer(buyer, _amount);
    }

    function refundFunds(
        uint256 _amount,
        uint256[] calldata _nonces,
        bytes[] calldata _signatures
    ) external notLocked notCompleted nonReentrant {
        require(
            _nonces.length == 2 && _signatures.length == 2,
            "Requires exactly two arguments"
        );

        bytes32 hash0 = calculateIntentHash(1, _nonces[0], _amount);
        bytes32 hash1 = calculateIntentHash(1, _nonces[1], _amount);

        address signer0 = _getSigner(hash0, _signatures[0]);
        address signer1 = _getSigner(hash1, _signatures[1]);

        require(signer0 != signer1, "Duplicate signer");
        require(
            _isParticipantSignature(hash0, _signatures[0]) &&
                _isParticipantSignature(hash1, _signatures[1]),
            "Invalid signature"
        );

        invalidSignaturesHashes[hash0] = true;
        invalidSignaturesHashes[hash1] = true;

        _executeTransfer(buyer, _amount);
    }

    function _executeTransfer(address _recipient, uint256 _amount) private {
        balance -= _amount;
        token.safeTransfer(_recipient, _amount);
        if (_recipient == buyer) {
            emit FundsRefunded(buyer, _amount);
        } else {
            emit FundsReleased(seller, _amount);
        }
        if (balance == 0) {
            completed = true;
            emit EscrowCompleted();
        }
    }

    function setLocked(bool _locked) external onlyOwner {
        locked = _locked;
        emit EscrowLocked(_locked);
    }

    function _getSigner(
        bytes32 _hash,
        bytes calldata _signature
    ) private pure returns (address) {
        bytes32 hash = _hash.toEthSignedMessageHash();
        return hash.recover(_signature);
    }

    function calculateIntentHash(
        uint256 _intent,
        uint256 _nonce,
        uint256 _amount
    ) public view returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    address(this),
                    block.chainid,
                    _intent,
                    _nonce,
                    _amount
                )
            );
    }

    function _isParticipantSignature(
        bytes32 _hash,
        bytes calldata _signature
    ) private view returns (bool) {
        address signer = _getSigner(_hash, _signature);
        if (signer != seller && signer != buyer && signer != owner()) {
            return false;
        }
        if (invalidSignaturesHashes[_hash]) {
            return false;
        }
        return true;
    }

    function isValidSignature(
        bytes32 _hash,
        bytes calldata _signature
    ) public view returns (bool) {
        address signer = _getSigner(_hash, _signature);
        return !invalidSignaturesHashes[_hash] && _isParticipant(signer);
    }

    function invalidateSignature(
        bytes32 _hash,
        bytes calldata _signature
    ) external onlyParticipants notCompleted {
        require(
            _getSigner(_hash, _signature) == _msgSender(),
            "You can only invalidate a signature made by you"
        );
        require(isValidSignature(_hash, _signature), "Invalid signature");

        invalidSignaturesHashes[_hash] = true;
        signatureNonce++;
    }
}
