// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";

contract PaymentSplitter is Ownable {
    IERC20 private token;
    using SafeERC20 for IERC20;

    uint256 serviceFee;
    uint256 feeBase = 100000000;

    event PaymentReceived(
        uint256 code,
        uint256 ref,
        address sellerAddress,
        uint256 amount
    );

    constructor(
        IERC20 _token,
        address _owner,
        uint256 _serviceFee
    ) Ownable(_owner) {
        token = _token;
        serviceFee = _serviceFee;
    }

    function changeServiceFee(uint256 _serviceFee) external onlyOwner {
        serviceFee = _serviceFee;
    }

    function pay(
        uint256 _code,
        uint256 _ref,
        address _sellerAddress,
        uint256 _amount
    ) external {
        uint256 amountServiceFee = (_amount * serviceFee) / feeBase;

        token.safeTransferFrom(msg.sender, owner(), amountServiceFee);

        token.safeTransferFrom(
            msg.sender,
            _sellerAddress,
            _amount - serviceFee
        );

        emit PaymentReceived(_code, _ref, _sellerAddress, _amount);
    }
}
