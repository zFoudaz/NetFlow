interface NetFlowLogoProps {
  size?: number;
  showWordmark?: boolean;
  className?: string;
}

/**
 * Geometric isometric uppercase 'N' mark with sharp straight edges and green/teal facets.
 */
export function NetFlowLogo({
  size = 24,
  showWordmark = true,
  className = "",
}: NetFlowLogoProps) {
  return (
    <div className={`inline-flex items-center gap-2.5 select-none ${className}`}>
      <svg
        width={size}
        height={size}
        viewBox="0 0 64 64"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        aria-hidden="true"
        className="shrink-0"
      >
        {/* Left vertical pillar (front & shaded inner bevel) */}
        <polygon points="10,16 19,10 19,54 10,48" fill="#16A34A" />
        <polygon points="19,10 24,14 24,49 19,54" fill="#0F766E" />
        <polygon points="10,48 19,43 24,47 19,54" fill="#22C55E" />

        {/* Right vertical pillar (top isometric cap & teal/green planes) */}
        <polygon points="40,12 49,6 49,50 40,56" fill="#14B8A6" />
        <polygon points="49,6 54,10 54,46 49,50" fill="#0D9488" />
        <polygon points="40,12 49,6 54,10 45,16" fill="#4ADE80" />

        {/* Diagonal ribbon connecting top-left to bottom-right */}
        <polygon points="10,16 19,10 49,38 49,50" fill="#3ECF8E" />
        <polygon points="19,24 49,50 40,56 19,37" fill="#10B981" />
      </svg>

      {showWordmark && (
        <span className="text-[15px] font-semibold tracking-tight text-[#F3F4F6]">
          NetFlow
        </span>
      )}
    </div>
  );
}
