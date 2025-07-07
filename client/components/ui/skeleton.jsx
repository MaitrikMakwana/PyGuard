import { cn } from "@/lib/utils";

function Skeleton({
  className,
  ...props
}.HTMLAttributes) {
  return (
    <div
      className={cn("animate-pulse rounded-md bg-muted", className)}
      {...props}
    />
  );
}

export { Skeleton };
