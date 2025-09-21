// verifySignature.js
const { ethers } = require('ethers');

function verifySignature(address, message, signature){
  // recover address
  const recovered = ethers.verifyMessage(message, signature);
  return recovered.toLowerCase() === address.toLowerCase();
}

module.exports = { verifySignature };
