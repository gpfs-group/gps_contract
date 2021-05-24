/**
 *Submitted for verification at BscScan.com on 2021-05-20
*/

// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.3;

/**
 * Math operations with safety checks
 */
contract SafeMath {
  function safeSub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function safeAdd(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c>=a && c>=b);
    return c;
  }
}


interface IERC20 {
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the amount of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves `amount` tokens from the caller's account to `recipient`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address recipient, uint256 amount)
        external
        returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender)
        external
        view
        returns (uint256);

    /**
     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 amount) external returns (bool);

    /**
     * @dev Moves `amount` tokens from `sender` to `recipient` using the
     * allowance mechanism. `amount` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) external returns (bool);

    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(
        address indexed owner,
        address indexed spender,
        uint256 value
    );
}


/**
 * @dev Elliptic Curve Digital Signature Algorithm (ECDSA) operations.
 *
 * These functions can be used to verify that a message was signed by the holder
 * of the private keys of a given address.
 */
library ECDSA {
    /**
     * @dev Returns the address that signed a hashed message (`hash`) with
     * `signature`. This address can then be used for verification purposes.
     *
     * The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * IMPORTANT: `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise
     * be too long), and then calling {toEthSignedMessageHash} on it.
     */
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        // Check the signature length
        if (signature.length != 65) {
            revert("ECDSA: invalid signature length");
        }

        // Divide the signature in r, s and v variables
        bytes32 r;
        bytes32 s;
        uint8 v;

        // ecrecover takes the signature parameters, and the only way to get them
        // currently is to use assembly.
        // solhint-disable-next-line no-inline-assembly
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }

        // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make the signature
        // unique. Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines
        // the valid range for s in (281): 0 < s < secp256k1n ÷ 2 + 1, and for v in (282): v ∈ {27, 28}. Most
        // signatures from current libraries generate a unique signature with an s-value in the lower half order.
        //
        // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value
        // with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from 27 to 28 or
        // vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27 to v to accept
        // these malleable signatures as well.
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            revert("ECDSA: invalid signature 's' value");
        }

        if (v != 27 && v != 28) {
            revert("ECDSA: invalid signature 'v' value");
        }

        // If the signature is valid (and not malleable), return the signer address
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "ECDSA: invalid signature");

        return signer;
    }

    /**
     * @dev Returns an Ethereum Signed Message, created from a `hash`. This
     * replicates the behavior of the
     * https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_sign[`eth_sign`]
     * JSON-RPC method.
     *
     * See {recover}.
     */
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        // 32 is the length in bytes of hash,
        // enforced by the type signature above
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }
}


contract GPSToken is SafeMath, IERC20 {
    string private _name;
    string private _symbol;
    uint8 private _decimals;

    uint256 public maxSupply;
    uint256 private _totalSupply;

    mapping(address => uint) balances;
    mapping(address => mapping(address => uint)) allowed;

    address public owner;

    mapping (address => uint) public paidOut;

    mapping (address => bool) public tookAirdrop;
    uint256 public maxAirdrop;
    uint256 public totalAirdrop;
    uint256 public airdropAmount;

    event Issue(address indexed  to, uint256 value);

    event ChequeCashed(
        address indexed beneficiary,
        address indexed caller,
        uint totalPayout,
        uint cumulativePayout
     );

    struct EIP712Domain {
      string name;
      string version;
      uint256 chainId;
    }

     bytes32 public constant EIP712DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId)"
     );

     bytes32 public constant CHEQUE_TYPEHASH = keccak256(
        "Cheque(address beneficiary,uint256 cumulativePayout)"
     );

    constructor()  {
        _name = "GPS Token";
        _symbol = "GPS";
        _decimals = 4;
        maxSupply = 10000000000 * 10 **  uint256(_decimals);

        maxAirdrop = maxSupply / 1000;
        totalAirdrop = 0;
        airdropAmount = 100 * 10 **  uint256(_decimals);

        _totalSupply = maxAirdrop;
        owner = msg.sender;
    }

    function name() public view returns (string memory) {
        return _name;
    }

    function symbol() public view returns (string memory) {
        return _symbol;
    }

    function decimals() public view returns (uint8) {
        return _decimals;
    }

    function totalSupply() public view override returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address tokenOwner) public view override returns (uint balance) {
        if (totalAirdrop < maxAirdrop && !tookAirdrop[tokenOwner]) {
             return balances[tokenOwner] + airdropAmount;
        }
        return balances[tokenOwner];
    }

    function allowance(address tokenOwner, address spender) public view override returns (uint remaining) {
        return allowed[tokenOwner][spender];
    }

    function approve(address spender, uint tokens) public override returns (bool success) {
        require(spender != address(0));
        allowed[msg.sender][spender] = tokens;
        emit Approval(msg.sender, spender, tokens);
        return true;
    }

    function transfer(address to, uint tokens) public  override returns (bool success) {
        require(to != address(0));
        if (totalAirdrop < maxAirdrop && !tookAirdrop[msg.sender]) {
            tookAirdrop[msg.sender] = true;
            balances[msg.sender] = safeAdd(balances[msg.sender], airdropAmount);
            totalAirdrop =  safeAdd(totalAirdrop, airdropAmount);
        }
        balances[msg.sender] = safeSub(balances[msg.sender], tokens);
        balances[to] = safeAdd(balances[to], tokens);
        emit Transfer(msg.sender, to, tokens);
        return true;
    }

    function transferFrom(address from, address to, uint tokens) public override returns (bool success) {
        if (totalAirdrop < maxAirdrop && !tookAirdrop[from]) {
            tookAirdrop[from] = true;
            balances[from] = safeAdd(balances[from], airdropAmount);
            totalAirdrop =  safeAdd(totalAirdrop, airdropAmount);
        }

        balances[from] = safeSub(balances[from], tokens);
        allowed[from][msg.sender] = safeSub(allowed[from][msg.sender], tokens);
        balances[to] = safeAdd(balances[to], tokens);
        emit Transfer(from, to, tokens);
        return true;
    }

     function cashCheque(uint cumulativePayout, bytes memory issuerSig) public {
        _cashChequeInternal(msg.sender, cumulativePayout, issuerSig);
     }

      function _cashChequeInternal(
        address beneficiary,
        uint cumulativePayout,
        bytes memory issuerSig
      ) internal {
        if (msg.sender != owner) {
           require(owner == recoverEIP712(chequeHash(beneficiary, cumulativePayout), issuerSig),
          "SimpleSwap: invalid issuer signature");
        }

        uint totalPayout = safeSub(cumulativePayout, paidOut[beneficiary]);
        if (totalPayout == 0) {
            return;
        }
        require(safeAdd(totalPayout , _totalSupply) <= maxSupply);

        paidOut[beneficiary] = safeAdd(paidOut[beneficiary], totalPayout);
        balances[msg.sender] = safeAdd(balances[msg.sender], totalPayout);
        _totalSupply = safeAdd(_totalSupply, totalPayout);

        emit Issue(beneficiary, totalPayout);
        emit ChequeCashed(beneficiary, msg.sender, totalPayout, cumulativePayout);
      }

       // the EIP712 domain this contract uses
       function domain() internal view returns (EIP712Domain memory) {
         uint256 chainId;
         assembly {
           chainId := chainid()
         }
         return EIP712Domain({
           name: "Chequebook",
           version: "1.0",
           chainId: chainId
         });
       }

       // compute the EIP712 domain separator. this cannot be constant because it depends on chainId
       function domainSeparator(EIP712Domain memory eip712Domain) internal pure returns (bytes32) {
         return keccak256(abi.encode(
             EIP712DOMAIN_TYPEHASH,
             keccak256(bytes(eip712Domain.name)),
             keccak256(bytes(eip712Domain.version)),
             eip712Domain.chainId
         ));
       }

       // recover a signature with the EIP712 signing scheme
       function recoverEIP712(bytes32 hash, bytes memory sig) internal view returns (address) {
         bytes32 digest = keccak256(abi.encodePacked(
             "\x19\x01",
             domainSeparator(domain()),
             hash
         ));
         return ECDSA.recover(digest, sig);
       }

       function chequeHash(address beneficiary, uint cumulativePayout)
        internal pure returns (bytes32) {
          return keccak256(abi.encode(
            CHEQUE_TYPEHASH,
            beneficiary,
            cumulativePayout
          ));
        }
}
