
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title SecurePatterns
 * @dev A comprehensive smart contract demonstrating security best practices and design patterns
 * @notice This contract serves as an educational resource for learning secure smart contract development
 */
contract SecurePatterns is ReentrancyGuard, Ownable, Pausable {
    
    // State variables
    mapping(address => uint256) private balances;
    mapping(address => bool) private authorizedUsers;
    uint256 private totalDeposits;
    uint256 private constant MAX_DEPOSIT = 10 ether;
    uint256 private constant MIN_WITHDRAWAL = 0.01 ether;
    
    // Events - Following the CEI pattern (Checks, Effects, Interactions)
    event DepositMade(address indexed user, uint256 amount, uint256 timestamp);
    event WithdrawalMade(address indexed user, uint256 amount, uint256 timestamp);
    event UserAuthorized(address indexed user, address indexed authorizer);
    event UserRevoked(address indexed user, address indexed revoker);
    event EmergencyWithdrawal(address indexed owner, uint256 amount);
    
    // Custom errors for gas efficiency
    error InsufficientBalance(uint256 requested, uint256 available);
    error ExceedsMaximumDeposit(uint256 attempted, uint256 maximum);
    error BelowMinimumWithdrawal(uint256 attempted, uint256 minimum);
    error UnauthorizedUser(address user);
    error TransferFailed();
    error ZeroAmount();
    error ContractPaused();
    
    // Modifiers
    modifier onlyAuthorized() {
        if (!authorizedUsers[msg.sender] && msg.sender != owner()) {
            revert UnauthorizedUser(msg.sender);
        }
        _;
    }
    
    modifier validAmount(uint256 _amount) {
        if (_amount == 0) revert ZeroAmount();
        _;
    }
    
    modifier contractActive() {
        if (paused()) revert ContractPaused();
        _;
    }
    
    constructor() Ownable(msg.sender) {
        authorizedUsers[msg.sender] = true;
    }
    
    /**
     * @dev Secure deposit function implementing multiple security patterns
     * @notice Allows users to deposit ETH with proper validation and security checks
     * Security Patterns Demonstrated:
     * - Input validation
     * - Checks-Effects-Interactions (CEI) pattern
     * - Event emission
     * - Access control
     * - Overflow protection (Solidity 0.8+)
     * - Pausable functionality
     */
    function secureDeposit() 
        external 
        payable 
        nonReentrant 
        contractActive 
        validAmount(msg.value) 
    {
        // Checks
        if (msg.value > MAX_DEPOSIT) {
            revert ExceedsMaximumDeposit(msg.value, MAX_DEPOSIT);
        }
        
        // Effects (update state before external calls)
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        
        // Interactions (emit events)
        emit DepositMade(msg.sender, msg.value, block.timestamp);
    }
    
    /**
     * @dev Secure withdrawal function with comprehensive security measures
     * @param _amount The amount to withdraw
     * @notice Demonstrates pull-over-push pattern and reentrancy protection
     * Security Patterns Demonstrated:
     * - Pull-over-push pattern
     * - Reentrancy protection
     * - Input validation
     * - Balance verification
     * - Safe transfer pattern
     * - State updates before external calls
     */
    function secureWithdrawal(uint256 _amount) 
        external 
        nonReentrant 
        contractActive 
        validAmount(_amount) 
    {
        // Checks
        if (_amount < MIN_WITHDRAWAL) {
            revert BelowMinimumWithdrawal(_amount, MIN_WITHDRAWAL);
        }
        
        if (balances[msg.sender] < _amount) {
            revert InsufficientBalance(_amount, balances[msg.sender]);
        }
        
        // Effects (update state before external calls)
        balances[msg.sender] -= _amount;
        totalDeposits -= _amount;
        
        // Interactions (external call at the end)
        (bool success, ) = payable(msg.sender).call{value: _amount}("");
        if (!success) revert TransferFailed();
        
        emit WithdrawalMade(msg.sender, _amount, block.timestamp);
    }
    
    /**
     * @dev Administrative function demonstrating access control patterns
     * @param _user Address to authorize
     * @param _authorized Boolean indicating authorization status
     * @notice Only owner or already authorized users can authorize others
     * Security Patterns Demonstrated:
     * - Role-based access control
     * - Administrative functions protection
     * - Event logging for transparency
     */
    function manageUserAuthorization(address _user, bool _authorized) 
        external 
        onlyAuthorized 
        contractActive 
    {
        // Input validation
        require(_user != address(0), "Invalid user address");
        require(_user != owner(), "Cannot modify owner status");
        
        // Update authorization status
        authorizedUsers[_user] = _authorized;
        
        // Emit appropriate event
        if (_authorized) {
            emit UserAuthorized(_user, msg.sender);
        } else {
            emit UserRevoked(_user, msg.sender);
        }
    }
    
    // View functions for transparency
    function getBalance(address _user) external view returns (uint256) {
        return balances[_user];
    }
    
    function getTotalDeposits() external view returns (uint256) {
        return totalDeposits;
    }
    
    function isAuthorized(address _user) external view returns (bool) {
        return authorizedUsers[_user] || _user == owner();
    }
    
    function getContractBalance() external view returns (uint256) {
        return address(this).balance;
    }
    
    // Emergency functions (Circuit breaker pattern)
    function pause() external onlyOwner {
        _pause();
    }
    
    function unpause() external onlyOwner {
        _unpause();
    }
    
    /**
     * @dev Emergency withdrawal function for contract owner
     * @notice Should only be used in extreme circumstances
     * Demonstrates circuit breaker pattern
     */
    function emergencyWithdraw() external onlyOwner {
        uint256 contractBalance = address(this).balance;
        require(contractBalance > 0, "No funds to withdraw");
        
        (bool success, ) = payable(owner()).call{value: contractBalance}("");
        if (!success) revert TransferFailed();
        
        emit EmergencyWithdrawal(owner(), contractBalance);
    }
    
    // Prevent accidental ETH sends
    receive() external payable {
        revert("Use secureDeposit() function");
    }
    
    fallback() external payable {
        revert("Function not found");
    }
}
