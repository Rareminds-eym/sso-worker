import bcrypt from "bcryptjs";

const password = "DemoCollege123";
const saltRounds = 12;

bcrypt.hash(password, saltRounds, (err, hash) => {
  if (err) {
    console.error("Error generating hash:", err);
    process.exit(1);
  }
  console.log("Password:", password);
  console.log("Hash:", hash);
  console.log("\nCopy this hash to the seed file:");
  console.log(hash);
});
