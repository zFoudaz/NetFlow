import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import App from "../App";

describe("App", () => {
  it("mounts and renders the NetFlow title", () => {
    render(<App />);
    expect(screen.getByRole("heading", { name: "NetFlow" })).toBeTruthy();
  });
});
