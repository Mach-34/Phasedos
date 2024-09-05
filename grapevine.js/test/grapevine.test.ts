import * as GrapevineUtils from "../src/utils";
import { GrapevineWasm } from "../src/consts";

describe("Grapevine", () => {
    let wasm: GrapevineWasm;
    beforeAll(async () => {
        wasm = await GrapevineUtils.initGrapevineWasm();
    });
    it("Test the bn", async () => { 
        let x = 12348023482034820384023840238402834028340283402834023n;
        let y = await wasm.bigint_test(x);
    });
});