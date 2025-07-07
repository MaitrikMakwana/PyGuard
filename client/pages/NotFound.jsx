import { useLocation } from "react-router-dom";
import { useEffect } from "react";
import Navigation from "../components/Navigation";

const NotFound = () => {
  const location = useLocation();

  useEffect(() => {
    console.error(
      "404 Error: User attempted to access non-existent route:",
      location.pathname,
    );
  }, [location.pathname]);

  return (
    <div className="min-h-screen bg-slate-900">
      <Navigation />
      <div className="min-h-screen flex items-center justify-center section-padding">
        <div className="text-center">
          <div className="mb-8">
            <div className="text-8xl font-bold gradient-text mb-4">404</div>
            <h1 className="text-4xl font-bold text-white mb-4">
              Page Not Found
            </h1>
            <p className="text-xl text-gray-400 mb-8 max-w-md mx-auto">
              The page you're looking for doesn't exist or has been moved.
            </p>
          </div>

          <div className="space-y-4">
            <a
              href="/"
              className="btn-primary inline-flex items-center text-lg px-8 py-4"
            >
              <svg
                className="w-5 h-5 mr-2"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"
                />
              </svg>
              Return Home
            </a>
          </div>
        </div>
      </div>
    </div>
  );
};

export default NotFound;
