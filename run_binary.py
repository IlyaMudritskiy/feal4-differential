import os
from dataclasses import dataclass

@dataclass
class CheckKeys:
    bin_name: str = ""

    # Plaintext - ciphertext pairs
    plaintext: list = []
    ciphertext: list = []

    def transform_text(self, text: int) -> str:
        """Transform int text to d4 43 3c e1 79 61 48 2f."""

        start = 0
        stop = 2
        res = ""

        for _ in range(8):
            b = str(hex(text)[2:])[start:stop]
            res += b + " "
            start += 2
            stop += 2
        
        return res
    
    def plaintext_to_input(self, plaintext: int, ciphertext: int) -> str:
        """
        Outputs the plaintext and corresponding ciphertext 
        to be passed as an argument to program as:

        d4 43 3c e1 79 61 48 2f 7a 9a a3 55 4e b7 ff ee
        |------Plaintext------| |------Ciphertext-----|
        """

        return f"{self.transform_text(plaintext)}{self.transform_text(ciphertext)}"


    def run_file(self, plaintext: int, ciphertext: int) -> None:
        """
        Run the compiled code for checking keys.
        The output of binary will be put into a file.
        """

        params = self.plaintext_to_input(plaintext, ciphertext)
        command = f"./{self.bin_name} {params}"
        stream = os.popen(command)
        output = stream.read()

        try:
            with open("output.txt", "a") as f:
                f.write(output)
        except Exception as e:
            print(e)

        stream.close()

    def check(self) -> None:
        for i, value in enumerate(self.plaintext):
            print(f"[STARTED]    Current step: {i}/{len(value)}")
            self.run_file(value)
            i += 1


if __name__ == "__main__":
    check_keys = CheckKeys()
    check_keys.check()
