pragma solidity ^0.5.2;

contract Reward {
    uint constant public HalfTime = 4204800 ;
    uint constant public DecimalRate = 10000;
    uint constant public SetAuthorPeriod = 20000;
    // uint constant SeekDecimal = 10 ** 18;
    uint constant SeekDecimal = 10 ** 18;
    // uint constant MinePoolBurnt = 0;
    uint baseReward = 100 * SeekDecimal;
    // uint[2] inviteRewardRate = [500, 200];
    uint public baseHashRate = 18325193796;
    uint constant BaseStoragePrice = 275 * SeekDecimal;
    uint[21] public levelToStorage = [0, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576, 2097152, 4194304];
    uint[21] public rewardRate = [0, 2000, 3200, 3650, 4040, 4220, 4350, 4400, 4500, 4550, 4600, 4650, 4800, 5000, 5500, 6000, 6500, 7000, 8000, 9000, 10000];
    // uint[21] public burntCoinAmountToRate = [0, 2200*SeekDecimal, 4400*SeekDecimal, 6600* SeekDecimal, 17600*SeekDecimal,35200* SeekDecimal, 70400*SeekDecimal, 140800*SeekDecimal, 281600*SeekDecimal,563200*SeekDecimal,1126400*SeekDecimal,2252800*SeekDecimal,4505600*SeekDecimal, 9011200*SeekDecimal, 18022400*SeekDecimal, 36044800*SeekDecimal, 72089600*SeekDecimal, 142606336*SeekDecimal, 288358400*SeekDecimal, 576716800*SeekDecimal, 1153433600*SeekDecimal];
    address payable teamAddr = 0x54e6F8AF5FC2f585b269f5992A66cF6B2CfAa6e6;
    address payable intervalReward = 0x0D8Fe6b7CbF12EEDF2BeB2D0893D39B252590D8E;
    //矿工地址可以公开查询,能查到自己的邀请人,当前等级已烧币总量
    mapping(address => Account) public accounts;
    mapping (address => address) public authors;
    
    // mapping(address => MinePool) public minePools;

    event Register(address payable inviter, address payable miner);
    event LevelUp(address payable miner, uint stBuy, uint burntAmount);
    event SetAuthor(address indexed miner, address indexed author);
    
    
    
    
    struct Account {
        address payable owner;
        address payable inviter;
        address payable author;
        uint burntCoin;
        uint rewardRateLevel;
        uint maxStorage;
        uint setAuthorBlock;
    }
    
    // struct MinePool {
    //     uint rewardRate;
    //     uint burntCoin;
    //     uint[15] amountToLevel;
    //     bool isValid;
    // }

    // event MinePoolRegister(address minePool);
    

    constructor() public {
        address  payable[7]memory adresses = [0x54e6F8AF5FC2f585b269f5992A66cF6B2CfAa6e6, 0x0D8Fe6b7CbF12EEDF2BeB2D0893D39B252590D8E, 0xDFd46265A7E9914fF06aA1C4CCDaAA920F233E6E, 0xDEE9Ca00c5539C815d087E648315C1C2D1707e6a, 0x62321a674Dee7a327FD783D1f61d5480c64fdFBf, 0x626F4793d01786B47150D1134310a771D7731762, address(0)];
        for(uint i = 0; i< adresses.length - 1; i++) {
            authors[adresses[i]] = adresses[i];
            accounts[adresses[i]].author = adresses[i];
            accounts[adresses[i]].inviter = adresses[i + 1];
            accounts[adresses[i]].owner = adresses[i];
            accounts[adresses[i]].rewardRateLevel = 9;
            accounts[adresses[i]].maxStorage = 524288;
        }
    }

    // 获取矿工最大容量
    function getstorage(address payable miner) public view returns(uint) {
        if(authors[miner] != address(0)) {
            miner = address(uint160(authors[miner]));
        }
        return accounts[miner].maxStorage;
    }
    
    //注册
    function register(address payable inviter) public {
        require(accounts[msg.sender].owner == address(0) && inviter != msg.sender);
        require (authors[msg.sender] == address(0));
        require (inviter == address(0) || accounts[inviter].rewardRateLevel > 0);
        authors[msg.sender] = msg.sender;
        accounts[msg.sender].owner = msg.sender;
        accounts[msg.sender].inviter = inviter;
        accounts[msg.sender].author = msg.sender;
        emit Register(inviter, msg.sender);
    }

    function setAuthor(address payable author) public {
        require(author != address(0), 'address is null');
        require(authors[author] == address(0) || msg.sender == author, 'address invalid');
        require (accounts[msg.sender].setAuthorBlock == 0 || block.number - accounts[msg.sender].setAuthorBlock > SetAuthorPeriod);
        authors[accounts[msg.sender].author] = address(0);
        accounts[msg.sender].author = author;
        accounts[msg.sender].setAuthorBlock = block.number;
        authors[author] = msg.sender;
        emit SetAuthor(msg.sender, author);
    }

    //矿工烧币提升等级, 交易中需要发送下一等级所需要的币, 不能多不能少
    function levelUp() payable external {
        delegateLevelUp(msg.sender);
    }

    //替其他地址进行烧币
    function delegateLevelUp(address payable miner) payable public {
        require(accounts[miner].owner != address(0));
        require (msg.value > 0);
        uint amount = msg.value;
        uint currentHashRate = getblockhashrate(block.number);
        uint storagePrice = getCurrentStoragePrice(currentHashRate);
        require (storagePrice > 0);
        // require (amount % storagePrice == 0);
        accounts[miner].burntCoin += msg.value;
        uint stToBuy = amount / storagePrice;
        accounts[miner].maxStorage += stToBuy;
        while (accounts[miner].maxStorage >= levelToStorage[accounts[miner].rewardRateLevel + 1] && accounts[miner].rewardRateLevel < 20) {
            accounts[miner].rewardRateLevel ++;
        }
        intervalReward.transfer(msg.value * 500 / DecimalRate);
        emit LevelUp(miner, stToBuy, msg.value);
    }
    

    function getInviteRewardRate(uint i) view internal returns(uint) {
        if(block.number <= HalfTime) {
            if(i == 0) {
                return 500;
            } else if(i == 1) {
                return 300;
            } else if(i == 2) {
                return 200;
            } else {
                return 100;
            }
        } else {
            if(i == 0) {
                return 300;
            } else if(i == 1) {
                return 150;
            } else if(i == 2) {
                return 100;
            } else {
                return 50;
            }
        }
    }

    function getCurrentStoragePrice(uint currentHashRate) view public returns(uint) {
        return BaseStoragePrice * baseHashRate / currentHashRate / SeekDecimal * SeekDecimal;
    }
    

    //获取提升等级需要的烧币数量, 传入需要提升的等级
    // function getNeedBurntCoin(uint level) public returns(uint){
    //     uint currentHashRate = getblockhashrate(block.number);
    //     return getNeedBurntCoinView(level, currentHashRate);
    // }

    // function getNeedBurntCoinView(uint level, uint hashRate) public view returns(uint){
    //     return burntCoinAmountToRate[level] * baseHashRate / hashRate;
    // }
    
    
    function reward(address[] memory benefactors, uint16[] memory kind) public view returns (address[] memory addresses, uint[] memory amounts) {
        address payable miner = address(uint160(benefactors[0]));
        if(authors[miner] != address(0)) {
            miner = address(uint160(authors[miner]));
        }
        require(accounts[miner].rewardRateLevel > 0);
        addresses = new address[](12);
        amounts = new uint[](12);
        uint total = baseReward / (2 ** (block.number / HalfTime)) * rewardRate[accounts[miner].rewardRateLevel] / DecimalRate;
        address inviter = accounts[miner].inviter;
        uint teamAwardRate = 1700;
        for(uint i = 0; i < 10; i++) {
            if(inviter == address(0)) {
                break;
            }
            addresses[i] = inviter;
            amounts[i] = total * getInviteRewardRate(i) / DecimalRate;
            if (teamAwardRate >= getInviteRewardRate(i)){
                teamAwardRate -= getInviteRewardRate(i);
            } else {
                teamAwardRate = 0;
            }
            inviter = accounts[inviter].inviter;
        }
        addresses[10] = teamAddr;
        amounts[10] = total * teamAwardRate / DecimalRate;
        addresses[11] = miner;
        amounts[11] = total * 8300 / DecimalRate;
        return (addresses, amounts);
    }

    function getblockhashrate(uint256 blocknumber) public returns (uint256){
        bytes32[1]  memory input;
        bytes32[1]  memory output;
        input[0] = bytes32(blocknumber);
        assembly {
            if iszero(call(not(0), 0x0E, 0, input, 0x20, output, 0x20)) {
              revert(0, 0)
            }
        }
        return uint256(output[0]);

    }
}
