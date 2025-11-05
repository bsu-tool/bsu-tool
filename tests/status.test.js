import { isWorking } from "../src/lib/status.js";

test("isWorking returns true", () => {
  expect(isWorking()).toBe(true);
});
