import { DemoResponse } from "../../shared/api.js";

export const handleDemo = (req, res) => {
  const response = {
    message: "Hello from Express server",
  };
  res.status(200).json(response);
};
