import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const styles = readFileSync("src/styles.css", "utf8");

describe("responsive frontend styles", () => {
  it("does not force a page wider than a narrow viewport", () => {
    expect(styles).toMatch(/body \{\s*margin: 0;\s*min-width: 0;/);
  });

  it("keeps dashboard content in one column at the tablet breakpoint", () => {
    expect(styles).toMatch(
      /@media \(max-width: 980px\) \{[\s\S]*?\.dashboard-grid,[\s\S]*?\.content-grid,[\s\S]*?grid-template-columns: minmax\(0, 1fr\);/
    );
  });

  it("keeps dense data legible and keyboard-discoverable at the mobile breakpoint", () => {
    expect(styles).toMatch(
      /@media \(max-width: 640px\) \{[\s\S]*?\.table-wrap \{[\s\S]*?border: 1px solid #d9e0ea;[\s\S]*?\.table-wrap table \{[\s\S]*?min-width: 42rem;[\s\S]*?\.table-scroll-hint \{[\s\S]*?display: block;/
    );
    expect(styles).toMatch(
      /@media \(max-width: 640px\) \{[\s\S]*?\.summary-list,[\s\S]*?\.compact-list \{[\s\S]*?grid-template-columns: 1fr;[\s\S]*?pre \{[\s\S]*?max-height: 24rem;/
    );
  });

  it("constrains the native file picker so it cannot widen a narrow project upload panel", () => {
    expect(styles).toMatch(
      /\.upload-file-field input \{\s*width: 100%;\s*min-width: 0;\s*\}/
    );
  });

  it("allows the advanced-audit introduction to shrink inside a narrow grid", () => {
    expect(styles).toMatch(
      /\.advanced-audits \{[\s\S]*?grid-template-columns: minmax\(0, 1fr\);[\s\S]*?\.advanced-audits-intro \{[\s\S]*?flex-wrap: wrap;[\s\S]*?min-width: 0;/
    );
  });

  it("keeps advanced audit controls visually hidden until their disclosure is opened", () => {
    expect(styles).toMatch(
      /\.advanced-audits-content\[hidden\] \{\s*display: none;\s*\}/
    );
  });

  it("keeps compact filter controls inside a narrow viewport while retaining their own scroll affordance", () => {
    expect(styles).toMatch(
      /@media \(max-width: 640px\) \{[\s\S]*?\.filter-bar \{\s*align-items: stretch;\s*flex-direction: column;\s*width: 100%;\s*min-width: 0;\s*\}[\s\S]*?\.segmented-control \{\s*width: 100%;\s*min-width: 0;\s*overflow-x: auto;\s*\}/
    );
  });

  it("contains the workflow-step scroller instead of letting its intrinsic links widen the page", () => {
    expect(styles).toMatch(
      /\.workflow-nav \{\s*display: flex;\s*gap: 0\.35rem;\s*min-width: 0;\s*max-width: 100%;\s*overflow-x: auto;\s*\}/
    );
  });

  it("constrains analysis selectors whose option text is wider than a phone viewport", () => {
    expect(styles).toMatch(
      /\.auth-field select \{\s*min-height: 2\.25rem;\s*width: 100%;\s*min-width: 0;\s*max-width: 100%;/
    );
  });

  it("wraps technical metadata labels before they can overlap a report value", () => {
    expect(styles).toMatch(
      /\.summary-list dt,\s*\.compact-list dt \{\s*min-width: 0;\s*overflow-wrap: anywhere;/
    );
  });

  it("lets report sections shrink inside a phone-sized result panel", () => {
    expect(styles).toMatch(
      /\.report-layout \{\s*display: grid;\s*grid-template-columns: minmax\(0, 1fr\);\s*min-width: 0;/
    );
    expect(styles).toMatch(
      /\.report-section \{\s*display: grid;\s*grid-template-columns: minmax\(0, 1fr\);\s*min-width: 0;/
    );
    expect(styles).toMatch(
      /\.dependency-groups,[\s\S]*?\.archive-entry-list \{\s*display: grid;\s*grid-template-columns: minmax\(0, 1fr\);\s*min-width: 0;/
    );
    expect(styles).not.toMatch(/(?:html|body)[^}]*overflow-x:\s*hidden/);
  });

  it("keeps public-advisory filters responsive without relying on a horizontal page scroll", () => {
    expect(styles).toMatch(
      /\.project-vulnerability-filters \{\s*display: grid;\s*grid-template-columns: minmax\(16rem, 1\.5fr\) repeat\(4, minmax\(10rem, 0\.55fr\)\);/
    );
    expect(styles).toMatch(
      /@media \(max-width: 980px\) \{[\s\S]*?\.project-vulnerability-filters,[\s\S]*?grid-template-columns: minmax\(0, 1fr\);/
    );
    expect(styles).toMatch(
      /@media \(max-width: 980px\) \{[\s\S]*?\.project-vulnerability-actions \{\s*width: 100%;\s*\}[\s\S]*?\.project-vulnerability-panel \.panel-header \{\s*align-items: stretch;\s*flex-direction: column;\s*\}/
    );
    expect(styles).toMatch(
      /@media \(max-width: 640px\) \{[\s\S]*?\.project-vulnerability-actions \{\s*display: grid;\s*grid-template-columns: minmax\(0, 1fr\);\s*\}[\s\S]*?\.project-vulnerability-actions button \{\s*width: 100%;\s*min-width: 0;\s*white-space: normal;\s*\}/
    );
  });

  it("stacks the public-intelligence workflow, status and priority summary on narrow screens", () => {
    expect(styles).toMatch(
      /\.project-vulnerability-workflow \{\s*display: grid;\s*grid-template-columns: repeat\(3, minmax\(0, 1fr\)\);/
    );
    expect(styles).toMatch(
      /@media \(max-width: 980px\) \{[\s\S]*?\.project-vulnerability-workflow \{\s*grid-template-columns: minmax\(0, 1fr\);[\s\S]*?\.project-vulnerability-card-summary \{\s*grid-template-columns: minmax\(0, 1fr\);/
    );
    expect(styles).toMatch(
      /@media \(max-width: 640px\) \{[\s\S]*?\.project-vulnerability-status,[\s\S]*?\.project-vulnerability-priority-summary \{\s*grid-template-columns: minmax\(0, 1fr\);[\s\S]*?\.project-vulnerability-workflow button \{\s*width: 100%;/
    );
  });

  it("stacks the archive coverage preview before a phone-sized upload can overflow", () => {
    expect(styles).toMatch(
      /@media \(max-width: 640px\) \{[\s\S]*?\.project-archive-preflight-summary \{\s*grid-template-columns: minmax\(0, 1fr\);[\s\S]*?\.project-archive-preflight \.query-warning \.secondary-button \{\s*width: 100%;/
    );
  });

  it("lets the recent-project onboarding row shrink without widening a phone viewport", () => {
    expect(styles).toMatch(
      /\.project-start-copy \{[\s\S]*?grid-template-columns: minmax\(0, 1fr\);[\s\S]*?min-width: 0;/
    );
    expect(styles).toMatch(
      /\.recent-projects button \{[\s\S]*?max-width: 100%;[\s\S]*?min-width: 0;[\s\S]*?white-space: normal;/
    );
  });

  it("allows finding cards with long technical identifiers to shrink inside a phone panel", () => {
    expect(styles).toMatch(
      /\.project-finding-list \{\s*display: grid;\s*grid-template-columns: minmax\(0, 1fr\);[\s\S]*?min-width: 0;[\s\S]*?\.project-finding-card \{\s*min-width: 0;/
    );
    expect(styles).toMatch(
      /\.project-finding-toggle > span:first-child \{\s*display: grid;\s*gap: 0\.18rem;\s*min-width: 0;\s*max-width: 100%;\s*\}[\s\S]*?\.project-finding-toggle > span:first-child > \* \{\s*min-width: 0;\s*overflow-wrap: anywhere;/
    );
    expect(styles).not.toMatch(/(?:html|body)[^}]*overflow-x:\s*hidden/);
  });

  it("contains Active deletion labels and controls within a narrow asset card", () => {
    expect(styles).toMatch(
      /\.active-deletion-scope li > div \{[^}]*flex-wrap: wrap;/
    );
    expect(styles).toMatch(
      /\.active-deletion-scope \.status-pill \{[^}]*max-width: 100%;[^}]*white-space: normal;/
    );
    expect(styles).toMatch(
      /\.active-deletion-panel button \{[^}]*width: 100%;[^}]*min-width: 0;[^}]*max-width: 100%;/
    );
    expect(styles).toMatch(
      /\.active-asset-detail > button \{[^}]*width: 100%;[^}]*min-width: 0;[^}]*max-width: 100%;[^}]*white-space: normal;/
    );
  });

  it("stacks the Active evidence period and download affordance on narrow cards", () => {
    expect(styles).toMatch(
      /\.active-posture \{[^}]*grid-template-columns: minmax\(0, 1fr\);[^}]*min-width: 0;/
    );
    expect(styles).toMatch(
      /\.active-posture > \* \{[^}]*min-width: 0;[^}]*max-width: 100%;/
    );
    expect(styles).toMatch(
      /\.active-evidence-export \{[^}]*grid-template-columns: minmax\(0, 15rem\) minmax\(0, 1fr\);/
    );
    expect(styles).toMatch(
      /@media \(max-width: 760px\) \{[\s\S]*?\.active-evidence-export \{ grid-template-columns: 1fr; \}[\s\S]*?\.active-evidence-export \.secondary-button \{[^}]*width: 100%;[^}]*min-width: 0;[^}]*max-width: 100%;[^}]*white-space: normal;/
    );
    expect(styles).toMatch(
      /\.active-posture a\.secondary-button \{[^}]*min-height: 44px;[^}]*display: inline-flex;/
    );
  });

  it("keeps the Active audit preflight and download actions usable on narrow screens", () => {
    expect(styles).toMatch(
      /\.product-audit-export-controls \{[^}]*grid-template-columns: minmax\(10rem, \.65fr\) minmax\(15rem, 1\.35fr\) auto;/
    );
    expect(styles).toMatch(
      /\.product-audit-export-actions a \{[^}]*min-height: 44px;[^}]*display: inline-flex;/
    );
    expect(styles).toMatch(
      /\.product-audit-export-controls select \{[^}]*min-height: 44px;[^}]*\}[\s\S]*?\.product-audit-export-controls button \{[^}]*min-height: 44px;/
    );
    expect(styles).toMatch(
      /@media \(max-width: 640px\) \{[\s\S]*?\.product-audit-export-controls,[\s\S]*?\.product-audit-export-preview dl \{[\s\S]*?grid-template-columns: 1fr;[\s\S]*?\.product-audit-export-actions a \{[\s\S]*?width: 100%;/
    );
  });

  it("keeps the weekly report consent aligned without an anonymous flex wrap", () => {
    expect(styles).toMatch(
      /\.active-weekly-report \.checkbox-row \{[^}]*display: grid;[^}]*grid-template-columns: 44px minmax\(0, 1fr\);[^}]*min-width: 0;/
    );
    expect(styles).toMatch(
      /\.active-weekly-report \.checkbox-row input \{[^}]*justify-self: center;/
    );
  });

  it("bounds the expanded Active portfolio controls and stacks paging on phones", () => {
    expect(styles).toMatch(
      /\.active-center-toolbar,[\s\S]*?grid-template-columns: minmax\(15rem, 2fr\) repeat\(4, minmax\(8rem, 1fr\)\) auto;/
    );
    expect(styles).toMatch(
      /\.active-page-controls \{[^}]*grid-template-columns: minmax\(0, 1fr\) auto;[^}]*\}/
    );
    expect(styles).toMatch(
      /@media \(max-width: 760px\) \{[\s\S]*?\.active-center-toolbar,[\s\S]*?grid-template-columns: 1fr;[\s\S]*?\.active-page-controls \{ grid-template-columns: 1fr; \}[\s\S]*?\.active-page-controls button \{[^}]*width: 100%;[^}]*white-space: normal;/
    );
    expect(styles).toMatch(
      /\.active-batch-form summary \{[^}]*min-height: 44px;[^}]*display: flex;[^}]*align-items: center;/
    );
    expect(styles).toMatch(
      /\.active-batch-picker input\[type="file"\] \{[^}]*width: 100%;[^}]*min-width: 0;[^}]*max-width: 100%;/
    );
  });
});
