
(function (root) {
  "use strict";

  const MAX_SEED = 0xFFFF;
  const LFSR_PERIOD_BITS = 0xFFFF;

  function validateSeed(seed) {
      if (!Number.isInteger(seed)) {
          throw new TypeError("seed must be an integer");
      }

      if (seed < 1 || seed > MAX_SEED) {
          throw new RangeError(
              "seed must be between 1 and 65535"
          );
      }
  }

  function validateLength(length) {
      if (!Number.isInteger(length)) {
          throw new TypeError("length must be an integer");
      }

      if (length < 0) {
          throw new RangeError("length cannot be negative");
      }
  }

  function validateOffset(offset) {
      if (!Number.isInteger(offset)) {
          throw new TypeError("offset must be an integer");
      }

      if (offset < 0) {
          throw new RangeError("offset cannot be negative");
      }
  }

  function nextBit(state) {
      if (!Number.isInteger(state)) {
          throw new TypeError("state must be an integer");
      }

      if (state < 1 || state > MAX_SEED) {
          throw new RangeError(
              "state must be a non-zero 16-bit integer"
          );
      }

      // Output: least significant bit.
      const outputBit = state & 1;

      // Feedback taps: bits 0, 2, 3, and 5.
      const feedback =
          ((state >> 0) & 1) ^
          ((state >> 2) & 1) ^
          ((state >> 3) & 1) ^
          ((state >> 5) & 1);

      // Shift right and insert feedback at bit 15.
      const nextState =
          (state >>> 1) | (feedback << 15);

      return {
          bit: outputBit,
          state: nextState
      };
  }

  function keystream(length, seed, offset = 0) {
      validateSeed(seed);
      validateLength(length);
      validateOffset(offset);

      let state = seed;

      // Skip offset bytes.
      const bitsToSkip = offset * 8;

      for (let i = 0; i < bitsToSkip; i++) {
          state = nextBit(state).state;
      }

      const result = new Uint8Array(length);

      for (let i = 0; i < length; i++) {
          let byteValue = 0;

          // First generated bit becomes the MSB.
          for (let bitPosition = 7; bitPosition >= 0; bitPosition--) {
              const resultBit = nextBit(state);

              byteValue |= resultBit.bit << bitPosition;
              state = resultBit.state;
          }

          result[i] = byteValue;
      }

      return result;
  }

  function xorBytes(data, seed, offset = 0) {
      validateSeed(seed);
      validateOffset(offset);

      if (
          !(data instanceof Uint8Array) &&
          !(data instanceof ArrayBuffer)
      ) {
          throw new TypeError(
              "data must be a Uint8Array or ArrayBuffer"
          );
      }

      const input = data instanceof ArrayBuffer
          ? new Uint8Array(data)
          : data;

      const key = keystream(
          input.length,
          seed,
          offset
      );

      const result = new Uint8Array(input.length);

      for (let i = 0; i < input.length; i++) {
          result[i] = input[i] ^ key[i];
      }

      return result;
  }

  root.LfsrCipher = Object.freeze({
      MAX_SEED,
      LFSR_PERIOD_BITS,
      nextBit,
      keystream,
      xorBytes
  });

  if (typeof module !== "undefined" && module.exports) {
    module.exports = root.LfsrCipher;
  }

})(typeof self !== "undefined" ? self : globalThis);
