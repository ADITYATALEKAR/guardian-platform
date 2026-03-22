import type { SVGProps } from "react";

type PetalProps = {
  rotate: number;
  scaleX: number;
  scaleY: number;
  fillColor: string;
};

const PETAL_PATH =
  "M0 0C-7-8-13-20-12-37C-11-51-5-65 0-78C5-65 11-51 12-37C13-20 7-8 0 0Z";

function Petal({ rotate, scaleX, scaleY, fillColor }: PetalProps) {
  return (
    <g transform={`translate(60 78) rotate(${rotate}) scale(${scaleX} ${scaleY})`}>
      <path d={PETAL_PATH} fill={fillColor} />
      <path d={PETAL_PATH} />
    </g>
  );
}

export function BrandLotus(props: SVGProps<SVGSVGElement>) {
  const petalFill = "var(--brand-lotus-fill, transparent)";
  const sideScaleX = 0.9;
  const sideScaleY = 0.9;

  return (
    <svg
      viewBox="0 0 132 88"
      fill="none"
      stroke="currentColor"
      strokeWidth="4"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      shapeRendering="geometricPrecision"
      {...props}
    >
      <g transform="translate(6 0)">
        <Petal rotate={-62} scaleX={sideScaleX} scaleY={sideScaleY} fillColor={petalFill} />
        <Petal rotate={62} scaleX={sideScaleX} scaleY={sideScaleY} fillColor={petalFill} />
        <Petal rotate={-30} scaleX={sideScaleX} scaleY={sideScaleY} fillColor={petalFill} />
        <Petal rotate={30} scaleX={sideScaleX} scaleY={sideScaleY} fillColor={petalFill} />
        <Petal rotate={0} scaleX={0.82} scaleY={1.02} fillColor={petalFill} />
      </g>
    </svg>
  );
}
