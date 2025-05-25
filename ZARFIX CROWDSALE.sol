// SPDX-License-Identifier: MIT
pragma solidity >=0.8.20 <0.9.0;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {IERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

interface AggregatorV3Interface {
    function latestRoundData() external view returns (
        uint80 roundId,
        int256 price,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    );
}


contract ZarfixCrowdsale is 
    Initializable, 
    UUPSUpgradeable, 
    OwnableUpgradeable, 
    PausableUpgradeable, 
    ReentrancyGuardUpgradeable 
{
    // ============ CONSTANTS ============
    uint256 private constant MAX_FEE_PERCENT = 1000; // 10%
    uint256 private constant PRICE_DECIMALS = 1e26;
    uint256 private constant BNB_TO_USD_CONVERSION = 1e15;
    
    // User status bit flags
    uint256 private constant WHITELIST_FLAG = 0x1;
    uint256 private constant KYC_FLAG = 0x2;
    uint256 private constant BLACKLIST_FLAG = 0x4;

    // ============ STATE VARIABLES ============
    
    // Core configuration
    IERC20Upgradeable public token;
    address public fundWallet;
    address public feeWallet;
    uint256 public feePercentage;
    
    // Pricing configuration
    uint256 public tokenPerUsd;
    AggregatorV3Interface  public priceOracle;
    bool public useOracle;
    uint256 public manualBnbPrice;
    bool public useManualPrice;
    
    // Sale configuration
    struct SaleConfig {
        uint256 startTime;
        uint256 endTime;
        uint256 maxPerTransaction;
        uint256 maxPerWallet;
        uint256 softCap;
        uint256 hardCap;
        uint256 totalSupply;
        uint256 totalSold;
        bool finalized;
        bool refundEnabled;
    }
    SaleConfig public saleConfig;
    
    // Anti-bot and security
    struct SecurityConfig {
        uint256 antiWhaleTxLimit;
        uint256 cooldownPeriod;
        uint256 multisigThreshold;
        uint256 totalFeeCollected;
    }
    SecurityConfig public securityConfig;
    
    // Vesting configuration
    struct VestingConfig {
        uint256 duration;
        uint256 cliffPeriod;
        uint256 cliffPercentage;
    }
    VestingConfig public defaultVesting;
    VestingConfig public airdropVesting;
    
    // Airdrop configuration
    struct AirdropConfig {
        bytes32 merkleRoot;
        uint256 deadline;
        uint256 totalSupply;
    }
    AirdropConfig public airdropConfig;
    
    // ============ MAPPINGS ============
    mapping(address => uint256) public userPurchases;
    mapping(address => uint256) public userStatus;
    mapping(address => uint256) public refundableAmounts;
    mapping(address => uint256) public lastPurchaseTime;
    mapping(address => uint256) public lastPurchaseBlock;
    mapping(address => bool) public airdropClaimed;
    mapping(bytes32 => bool) public processedPayments;
    mapping(address => bool) public multisigSigners;
    mapping(bytes32 => uint256) public multisigApprovals;
    
    // Vesting information
    struct VestingInfo {
        uint256 totalAmount;
        uint256 claimedAmount;
        uint256 startTime;
        uint256 duration;
        uint256 cliffPeriod;
        uint256 cliffPercentage;
        bool isActive;
    }
    mapping(address => VestingInfo) public vestingSchedules;
    
    // ============ EVENTS ============
    event TokensPurchased(address indexed buyer, uint256 tokenAmount, uint256 bnbPaid);
    event TokensClaimed(address indexed user, uint256 amount);
    event AirdropClaimed(address indexed user, uint256 amount);
    event RefundProcessed(address indexed user, uint256 amount);
    event FeeTransferred(address indexed feeWallet, uint256 amount);
    event SaleFinalized(uint256 totalRaised);
    event VestingScheduleCreated(address indexed user, uint256 amount);
    event BatchVestingCreated(address[] users, uint256[] amounts);
    event FiatPaymentProcessed(address indexed recipient, uint256 amount, bytes32 indexed paymentId);
    event ConfigurationUpdated(string indexed configType, uint256 value);
    event SecurityParametersUpdated(uint256 antiWhaleLimit, uint256 cooldown);
    event ZarfixCrowdsaleInitialized(address token, address fundWallet, address feeWallet);
    
    // ============ MODIFIERS ============
    modifier onlyDuringSale() {
        require(
            block.timestamp >= saleConfig.startTime && 
            block.timestamp <= saleConfig.endTime, 
            "Sale not active"
        );
        _;
    }
    
    modifier onlyValidUser(address user) {
        require(!_isBlacklisted(user), "User blacklisted");
        require(_isWhitelisted(user), "User not whitelisted");
        require(_isKYCVerified(user), "User not KYC verified");
        _;
    }
    
    modifier antiBot() {
        require(
            block.number > lastPurchaseBlock[msg.sender], 
            "Only one transaction per block allowed"
        );
        lastPurchaseBlock[msg.sender] = block.number;
        _;
    }
    
    modifier cooldownCheck() {
        require(
            block.timestamp >= lastPurchaseTime[msg.sender] + securityConfig.cooldownPeriod,
            "Cooldown period active"
        );
        _;
    }
    
    modifier onlyMultisig(bytes32 actionId) {
        require(multisigSigners[msg.sender], "Not authorized multisig signer");
        multisigApprovals[actionId]++;
        require(
            multisigApprovals[actionId] >= securityConfig.multisigThreshold,
            "Insufficient multisig approvals"
        );
        delete multisigApprovals[actionId];
        _;
    }
    
    // ============ INITIALIZATION ============
    function initialize(
        address _token,
        address _fundWallet,
        address _feeWallet,
        uint256 _feePercentage
    ) public initializer {
        require(_token != address(0), "Invalid token address");
        require(_fundWallet != address(0), "Invalid fund wallet");
        require(_feeWallet != address(0), "Invalid fee wallet");
        require(_feePercentage <= MAX_FEE_PERCENT, "Fee percentage too high");
        
        __Ownable_init(_msgSender());
        __UUPSUpgradeable_init();
        __Pausable_init();
        __ReentrancyGuard_init();
        
        token = IERC20Upgradeable(_token);
        fundWallet = _fundWallet;
        feeWallet = _feeWallet;
        feePercentage = _feePercentage;
        
        // Default configuration
        saleConfig.refundEnabled = true;
        securityConfig.multisigThreshold = 1;
        
        emit ZarfixCrowdsaleInitialized(_token, _fundWallet, _feeWallet);
    }
    
    // ============ PURCHASE FUNCTIONS ============
    receive() external payable {
        purchaseTokens();
    }
    
    function purchaseTokens() 
        public 
        payable 
        whenNotPaused 
        nonReentrant 
        antiBot 
        cooldownCheck 
        onlyDuringSale 
        onlyValidUser(msg.sender) 
    {
        require(msg.value > 0, "Invalid BNB amount");
        
        uint256 tokenAmount = _calculateTokenAmount(msg.value);
        
        _validatePurchase(msg.sender, tokenAmount);
        _processPurchase(msg.sender, tokenAmount, msg.value);
        _createVestingSchedule(
            msg.sender, 
            tokenAmount, 
            defaultVesting.duration,
            defaultVesting.cliffPeriod,
            defaultVesting.cliffPercentage
        );
        
        emit TokensPurchased(msg.sender, tokenAmount, msg.value);
    }
    
    function _validatePurchase(address buyer, uint256 tokenAmount) private view {
        require(tokenAmount <= saleConfig.maxPerTransaction, "Exceeds max per transaction");
        require(tokenAmount <= securityConfig.antiWhaleTxLimit, "Exceeds anti-whale limit");
        require(
            userPurchases[buyer] + tokenAmount <= saleConfig.maxPerWallet,
            "Exceeds wallet limit"
        );
        require(
            saleConfig.totalSold + tokenAmount <= saleConfig.hardCap,
            "Exceeds hard cap"
        );
        require(
            saleConfig.totalSold + tokenAmount <= saleConfig.totalSupply,
            "Exceeds total supply"
        );
    }
    
    function _processPurchase(address buyer, uint256 tokenAmount, uint256 bnbAmount) private {
        userPurchases[buyer] += tokenAmount;
        saleConfig.totalSold += tokenAmount;
        refundableAmounts[buyer] += bnbAmount;
        lastPurchaseTime[buyer] = block.timestamp;
        
        // Process fee
        if (feePercentage > 0) {
            uint256 feeAmount = (bnbAmount * feePercentage) / 10000;
            securityConfig.totalFeeCollected += feeAmount;
            payable(feeWallet).transfer(feeAmount);
            emit FeeTransferred(feeWallet, feeAmount);
        }
    }
    
    // ============ PRICE CALCULATION ============
    function _calculateTokenAmount(uint256 bnbAmount) private view returns (uint256) {
        uint256 usdAmount = _getBnbToUsdAmount(bnbAmount);
        return usdAmount * tokenPerUsd;
    }
    
    function _getBnbToUsdAmount(uint256 bnbAmount) private view returns (uint256) {
        if (useManualPrice) {
            return (bnbAmount * manualBnbPrice) / 1e18;
        }
        
        if (useOracle) {
            require(address(priceOracle) != address(0), "Oracle not configured");
            (, int256 price, , ,) = priceOracle.latestRoundData();
            require(price > 0, "Invalid oracle price");
            return (bnbAmount * uint256(price)) / PRICE_DECIMALS;
        }
        
        // Fallback to simple conversion
        return bnbAmount / BNB_TO_USD_CONVERSION;
    }
    
    // ============ VESTING FUNCTIONS ============
    function claimVestedTokens() external nonReentrant {
        VestingInfo storage vesting = vestingSchedules[msg.sender];
        require(vesting.isActive, "No active vesting schedule");
        require(vesting.totalAmount > 0, "No tokens to claim");
        
        uint256 claimableAmount = calculateClaimableAmount(msg.sender);
        require(claimableAmount > 0, "No tokens available for claim");
        
        vesting.claimedAmount += claimableAmount;
        token.transfer(msg.sender, claimableAmount);
        
        emit TokensClaimed(msg.sender, claimableAmount);
    }
    
    function calculateClaimableAmount(address user) public view returns (uint256) {
        VestingInfo memory vesting = vestingSchedules[user];
        
        if (!vesting.isActive || block.timestamp < vesting.startTime + vesting.cliffPeriod) {
            return 0;
        }
        
        uint256 elapsedTime = block.timestamp - vesting.startTime;
        if (elapsedTime >= vesting.duration) {
            return vesting.totalAmount - vesting.claimedAmount;
        }
        
        uint256 cliffAmount = (vesting.totalAmount * vesting.cliffPercentage) / 100;
        uint256 remainingAmount = vesting.totalAmount - cliffAmount;
        uint256 vestedAmount = (remainingAmount * (elapsedTime - vesting.cliffPeriod)) / 
                              (vesting.duration - vesting.cliffPeriod) + cliffAmount;
        
        return vestedAmount - vesting.claimedAmount;
    }
    
    function _createVestingSchedule(
        address user,
        uint256 amount,
        uint256 duration,
        uint256 cliffPeriod,
        uint256 cliffPercentage
    ) private {
        vestingSchedules[user] = VestingInfo({
            totalAmount: amount,
            claimedAmount: 0,
            startTime: block.timestamp,
            duration: duration,
            cliffPeriod: cliffPeriod,
            cliffPercentage: cliffPercentage,
            isActive: true
        });
        
        emit VestingScheduleCreated(user, amount);
    }
    
    // ============ AIRDROP FUNCTIONS ============
    function claimAirdrop(bytes32[] calldata proof, uint256 amount) external {
        require(block.timestamp <= airdropConfig.deadline, "Airdrop period expired");
        require(!airdropClaimed[msg.sender], "Airdrop already claimed");
        
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender, amount));
        require(
            MerkleProof.verify(proof, airdropConfig.merkleRoot, leaf),
            "Invalid merkle proof"
        );
        
        airdropClaimed[msg.sender] = true;
        airdropConfig.totalSupply += amount;
        
        _createVestingSchedule(
            msg.sender,
            amount,
            airdropVesting.duration,
            airdropVesting.cliffPeriod,
            airdropVesting.cliffPercentage
        );
        
        emit AirdropClaimed(msg.sender, amount);
    }
    
    // ============ REFUND FUNCTIONS ============
    function processRefund() external nonReentrant {
        require(saleConfig.refundEnabled, "Refunds not enabled");
        require(
            block.timestamp > saleConfig.endTime && saleConfig.totalSold < saleConfig.softCap,
            "Refund conditions not met"
        );
        
        uint256 refundAmount = refundableAmounts[msg.sender];
        require(refundAmount > 0, "No refund available");
        
        refundableAmounts[msg.sender] = 0;
        payable(msg.sender).transfer(refundAmount);
        
        emit RefundProcessed(msg.sender, refundAmount);
    }
    
    // ============ FIAT PAYMENT FUNCTIONS ============
    function processFiatPayment(
        address recipient,
        uint256 tokenAmount,
        bytes32 paymentId
    ) external onlyOwner onlyValidUser(recipient) {
        require(!processedPayments[paymentId], "Payment already processed");
        require(
            saleConfig.totalSold + tokenAmount <= saleConfig.totalSupply,
            "Exceeds total supply"
        );
        
        processedPayments[paymentId] = true;
        userPurchases[recipient] += tokenAmount;
        saleConfig.totalSold += tokenAmount;
        
        _createVestingSchedule(
            recipient,
            tokenAmount,
            defaultVesting.duration,
            defaultVesting.cliffPeriod,
            defaultVesting.cliffPercentage
        );
        
        emit TokensPurchased(recipient, tokenAmount, 0);
        emit FiatPaymentProcessed(recipient, tokenAmount, paymentId);
    }
    
    function batchProcessFiatPayments(
        address[] calldata recipients,
        uint256[] calldata amounts,
        bytes32[] calldata paymentIds
    ) external onlyOwner {
        require(
            recipients.length == amounts.length && amounts.length == paymentIds.length,
            "Array length mismatch"
        );
        
        for (uint256 i = 0; i < recipients.length; i++) {
            require(_isValidUser(recipients[i]), "Invalid user");
            require(!processedPayments[paymentIds[i]], "Payment already processed");
            require(
                saleConfig.totalSold + amounts[i] <= saleConfig.totalSupply,
                "Exceeds total supply"
            );
            
            processedPayments[paymentIds[i]] = true;
            userPurchases[recipients[i]] += amounts[i];
            saleConfig.totalSold += amounts[i];
            
            _createVestingSchedule(
                recipients[i],
                amounts[i],
                defaultVesting.duration,
                defaultVesting.cliffPeriod,
                defaultVesting.cliffPercentage
            );
            
            emit TokensPurchased(recipients[i], amounts[i], 0);
            emit FiatPaymentProcessed(recipients[i], amounts[i], paymentIds[i]);
        }
    }
    
    // ============ ADMIN FUNCTIONS ============
    function finalizeSale() external onlyMultisig(keccak256("finalize_sale")) {
        require(!saleConfig.finalized, "Sale already finalized");
        
        saleConfig.finalized = true;
        saleConfig.refundEnabled = false;
        
        emit SaleFinalized(address(this).balance);
    }
    
    function withdrawUnsoldTokens() external onlyMultisig(keccak256("withdraw_unsold")) {
        require(saleConfig.finalized, "Sale not finalized");
        
        uint256 unsoldAmount = token.balanceOf(address(this));
        if (unsoldAmount > 0) {
            token.transfer(fundWallet, unsoldAmount);
        }
    }
    
    function emergencyWithdraw(address recipient) external onlyOwner {
        require(recipient != address(0), "Invalid recipient");
        
        uint256 balance = address(this).balance;
        if (balance > 0) {
            payable(recipient).transfer(balance);
        }
    }
    
    // ============ CONFIGURATION FUNCTIONS ============
    function configureSale(
        uint256 startTime,
        uint256 endTime,
        uint256 maxPerTx,
        uint256 maxPerWallet,
        uint256 softCap,
        uint256 hardCap,
        uint256 totalSupply
    ) external onlyOwner {
        require(startTime < endTime, "Invalid time range");
        require(softCap <= hardCap, "Invalid cap configuration");
        
        saleConfig.startTime = startTime;
        saleConfig.endTime = endTime;
        saleConfig.maxPerTransaction = maxPerTx;
        saleConfig.maxPerWallet = maxPerWallet;
        saleConfig.softCap = softCap;
        saleConfig.hardCap = hardCap;
        saleConfig.totalSupply = totalSupply;
    }
    
    function configureVesting(
        uint256 duration,
        uint256 cliffPeriod,
        uint256 cliffPercentage
    ) external onlyOwner {
        require(cliffPeriod <= duration, "Invalid cliff configuration");
        require(cliffPercentage <= 100, "Invalid cliff percentage");
        
        defaultVesting.duration = duration;
        defaultVesting.cliffPeriod = cliffPeriod;
        defaultVesting.cliffPercentage = cliffPercentage;
    }
    
    function configureAirdropVesting(
        uint256 duration,
        uint256 cliffPeriod,
        uint256 cliffPercentage
    ) external onlyOwner {
        require(cliffPeriod <= duration, "Invalid cliff configuration");
        require(cliffPercentage <= 100, "Invalid cliff percentage");
        
        airdropVesting.duration = duration;
        airdropVesting.cliffPeriod = cliffPeriod;
        airdropVesting.cliffPercentage = cliffPercentage;
    }
    
    function configureSecurity(
        uint256 antiWhaleLimit,
        uint256 cooldownPeriod,
        uint256 multisigThreshold
    ) external onlyOwner {
        securityConfig.antiWhaleTxLimit = antiWhaleLimit;
        securityConfig.cooldownPeriod = cooldownPeriod;
        securityConfig.multisigThreshold = multisigThreshold;
        
        emit SecurityParametersUpdated(antiWhaleLimit, cooldownPeriod);
    }
    
    function configurePricing(
        uint256 _tokenPerUsd,
        address _oracle,
        bool _useOracle,
        uint256 _manualPrice,
        bool _useManualPrice
    ) external onlyOwner {
        tokenPerUsd = _tokenPerUsd;
        priceOracle = AggregatorV3Interface(_oracle);
        useOracle = _useOracle;
        manualBnbPrice = _manualPrice;
        useManualPrice = _useManualPrice;
    }
    
    function configureAirdrop(
        bytes32 merkleRoot,
        uint256 deadline
    ) external onlyOwner {
        airdropConfig.merkleRoot = merkleRoot;
        airdropConfig.deadline = deadline;
    }
    
    // ============ USER MANAGEMENT ============
    function setUserStatus(address user, uint256 status) external onlyOwner {
        userStatus[user] = status;
    }
    
    function batchSetUserStatus(
        address[] calldata users,
        uint256[] calldata statuses
    ) external onlyOwner {
        require(users.length == statuses.length, "Array length mismatch");
        
        for (uint256 i = 0; i < users.length; i++) {
            userStatus[users[i]] = statuses[i];
        }
    }
    
    function setMultisigSigner(address signer, bool status) external onlyOwner {
        multisigSigners[signer] = status;
    }
    
    // ============ BATCH OPERATIONS ============
    function batchClaimTokens(address[] calldata users) external onlyOwner {
        for (uint256 i = 0; i < users.length; i++) {
            address user = users[i];
            VestingInfo storage vesting = vestingSchedules[user];
            
            if (vesting.isActive && vesting.totalAmount > 0) {
                uint256 claimableAmount = calculateClaimableAmount(user);
                if (claimableAmount > 0) {
                    vesting.claimedAmount += claimableAmount;
                    token.transfer(user, claimableAmount);
                    emit TokensClaimed(user, claimableAmount);
                }
            }
        }
    }
    
    function batchCreateVesting(
        address[] calldata users,
        uint256[] calldata amounts,
        uint256[] calldata durations,
        uint256[] calldata cliffPeriods,
        uint256[] calldata cliffPercentages
    ) external onlyOwner {
        require(
            users.length == amounts.length &&
            amounts.length == durations.length &&
            durations.length == cliffPeriods.length &&
            cliffPeriods.length == cliffPercentages.length,
            "Array length mismatch"
        );
        
        for (uint256 i = 0; i < users.length; i++) {
            _createVestingSchedule(
                users[i],
                amounts[i],
                durations[i],
                cliffPeriods[i],
                cliffPercentages[i]
            );
        }
        
        emit BatchVestingCreated(users, amounts);
    }
    
    // ============ VIEW FUNCTIONS ============
    function getUserInfo(address user) external view returns (
        uint256 totalPurchased,
        uint256 claimableAmount,
        uint256 claimedAmount,
        uint256 refundableAmount,
        bool isWhitelisted,
        bool isKYCVerified,
        bool isBlacklisted
    ) {
        totalPurchased = userPurchases[user];
        claimableAmount = calculateClaimableAmount(user);
        claimedAmount = vestingSchedules[user].claimedAmount;
        refundableAmount = refundableAmounts[user];
        isWhitelisted = _isWhitelisted(user);
        isKYCVerified = _isKYCVerified(user);
        isBlacklisted = _isBlacklisted(user);
    }
    
    function getSaleInfo() external view returns (
        uint256 startTime,
        uint256 endTime,
        uint256 totalSold,
        uint256 totalSupply,
        uint256 softCap,
        uint256 hardCap,
        bool finalized,
        bool refundEnabled,
        uint256 currentPrice
    ) {
        startTime = saleConfig.startTime;
        endTime = saleConfig.endTime;
        totalSold = saleConfig.totalSold;
        totalSupply = saleConfig.totalSupply;
        softCap = saleConfig.softCap;
        hardCap = saleConfig.hardCap;
        finalized = saleConfig.finalized;
        refundEnabled = saleConfig.refundEnabled;
        currentPrice = tokenPerUsd;
    }
    
    function getVestingInfo(address user) external view returns (VestingInfo memory) {
        return vestingSchedules[user];
    }
    
    function getCurrentBnbPrice() external view returns (uint256) {
        require(address(priceOracle) != address(0), "Oracle not configured");
        (, int256 price, , ,) = priceOracle.latestRoundData();
        require(price > 0, "Invalid oracle price");
        return uint256(price);
    }
    
    // ============ INTERNAL HELPER FUNCTIONS ============
    function _isWhitelisted(address user) private view returns (bool) {
        return (userStatus[user] & WHITELIST_FLAG) != 0;
    }
    
    function _isKYCVerified(address user) private view returns (bool) {
        return (userStatus[user] & KYC_FLAG) != 0;
    }
    
    function _isBlacklisted(address user) private view returns (bool) {
        return (userStatus[user] & BLACKLIST_FLAG) != 0;
    }
    
    function _isValidUser(address user) private view returns (bool) {
        return _isWhitelisted(user) && _isKYCVerified(user) && !_isBlacklisted(user);
    }
    
    // ============ PAUSABLE FUNCTIONS ============
    function pause() external onlyOwner {
        _pause();
    }
    
    function unpause() external onlyOwner {
        _unpause();
    }
    
    // ============ UPGRADE AUTHORIZATION ============
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
    
    // ============ STORAGE GAP ============
    uint256[50] private __gap;
}